#include "curve.hpp"
#ifdef MADS_ENABLE_CURVE

#include "crypto/monocypher.h"
#include "crypto/nacl_box.h"
#include "entropy.hpp"
#include "zmtp_session.hpp"
#include <cstring>

namespace Mads {

namespace {

// ---------------------------------------------------------------------------
// Wire constants. Every offset below is from CURVE_PLAN.md Appendix A, which
// is itself taken from libzmq v4.3.5 -- none of it is inferred.
// ---------------------------------------------------------------------------
constexpr size_t HELLO_BODY = 200;   // A.2
constexpr size_t WELCOME_BODY = 168; // A.3

// A READY body is \x05READY(6) + short nonce(8) + tag(16) + ciphertext.
constexpr size_t READY_OVERHEAD = 6 + 8 + 16;

// Socket-Type is the only property sent: name len(1) + "Socket-Type"(11) +
// value len(4) + "PUB"/"SUB"/"REQ"(3) = 19. 32 leaves room without inviting
// anyone to add properties without re-checking SCRATCH_CAP.
constexpr size_t METADATA_CAP = 32;

// INITIATE (A.4) is the largest of the three bodies: 113 fixed prologue +
// 16-byte tag + 128-byte plaintext + metadata. One buffer serves HELLO,
// WELCOME and INITIATE because they never overlap in time (Sec 7.2).
constexpr size_t INITIATE_PROLOGUE = 113;
constexpr size_t SCRATCH_CAP = INITIATE_PROLOGUE + 16 + 128 + METADATA_CAP;

// 16-byte nonce prefixes (the trailing 8 bytes are the big-endian counter).
const char NONCE_HELLO[] = "CurveZMQHELLO---";
const char NONCE_INITIATE[] = "CurveZMQINITIATE";
const char NONCE_READY[] = "CurveZMQREADY---";
// 8-byte nonce prefixes (the trailing 16 bytes are random / peer-supplied).
const char NONCE_WELCOME[] = "WELCOME-";
const char NONCE_VOUCH[] = "VOUCH---";

// ---------------------------------------------------------------------------
// Working state. File-static rather than local, per Sec 7.2: these are the
// bytes this code owns, and keeping them off the stack is the part of the
// stack budget that is actually controllable. Together they are ~500 B of
// .bss that a disabled build does not link at all.
// ---------------------------------------------------------------------------
uint8_t g_scratch[SCRATCH_CAP];
uint8_t g_c_prime[32];   // c'  transient secret
uint8_t g_C_prime[32];   // C'  transient public
uint8_t g_k_Sc[32];      // beforenm(S,  c')  -- seals HELLO, opens WELCOME
uint8_t g_k_Spc[32];     // beforenm(S', c)   -- seals the vouch box
uint8_t g_S_prime[32];   // S'  server transient public
uint8_t g_cookie[96];
uint8_t g_vouch_tail[16];

CurveError g_err = CurveError::none;

void put_u64_be(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; ++i)
    p[i] = static_cast<uint8_t>((v >> (8 * (7 - i))) & 0xFF);
}

uint64_t get_u64_be(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i)
    v = (v << 8) | p[i];
  return v;
}

/// 24-byte nonce: 16-byte literal prefix || 8-byte big-endian counter.
void short_nonce(uint8_t out[24], const char *prefix16, uint64_t n) {
  memcpy(out, prefix16, 16);
  put_u64_be(out + 16, n);
}

/// 24-byte nonce: 8-byte literal prefix || 16 random or peer-supplied bytes.
void long_nonce(uint8_t out[24], const char *prefix8, const uint8_t tail[16]) {
  memcpy(out, prefix8, 8);
  memcpy(out + 8, tail, 16);
}

/// Everything that must not outlive the handshake. st.precom is deliberately
/// not here -- it is the one thing the session keeps.
void wipe_transients() {
  crypto_wipe(g_c_prime, sizeof(g_c_prime));
  crypto_wipe(g_C_prime, sizeof(g_C_prime));
  crypto_wipe(g_k_Sc, sizeof(g_k_Sc));
  crypto_wipe(g_k_Spc, sizeof(g_k_Spc));
  crypto_wipe(g_S_prime, sizeof(g_S_prime));
  crypto_wipe(g_cookie, sizeof(g_cookie));
  crypto_wipe(g_vouch_tail, sizeof(g_vouch_tail));
  crypto_wipe(g_scratch, sizeof(g_scratch));
}

bool fail(CurveError e, CurveState &st) {
  g_err = e;
  st.wipe();
  wipe_transients();
  return false;
}

bool send_command(Transport &t, const uint8_t *body, size_t len) {
  // zmtp_write_raw_header() picks the 2- or 9-byte form itself; INITIATE
  // crosses 255 bytes and genuinely needs the large form.
  if (!zmtp_write_raw_header(t, len, ZmtpSession::FLAG_COMMAND))
    return false;
  return t.write(body, len);
}

/// Reads one command frame into g_scratch. A body larger than the scratch is
/// a protocol error, never a buffer overrun.
bool recv_command(Transport &t, size_t &len_out, uint32_t timeout_ms) {
  uint8_t flags;
  uint64_t len;
  if (!zmtp_read_raw_header(t, flags, len, timeout_ms))
    return false;
  if (!(flags & ZmtpSession::FLAG_COMMAND))
    return false;
  if (len > SCRATCH_CAP)
    return false;
  if (len && t.read(g_scratch, static_cast<size_t>(len), timeout_ms) !=
                 static_cast<int>(len))
    return false;
  len_out = static_cast<size_t>(len);
  return true;
}

} // namespace

void CurveState::wipe() {
  crypto_wipe(precom, sizeof(precom));
  nonce_out = 0;
  nonce_in = 0;
  ready = false;
}

CurveError curve_last_error() { return g_err; }

void curve_note_error(CurveError e) { g_err = e; }

namespace {
/// Distinguishes "the peer hung up" from "we ran out of time". The two are
/// the same short read at the transport, but they mean very different things
/// to whoever is debugging: mid-handshake, a hang-up is overwhelmingly a
/// wrong `server_public` (see curve.hpp's note on `disconnected`).
CurveError read_failure(Transport &t) {
  return t.connected() ? CurveError::timeout : CurveError::disconnected;
}
} // namespace

bool curve_handshake(Transport &t, const CurveKeys &k, const char *socket_type,
                     uint32_t timeout_ms, CurveState &st) {
  g_err = CurveError::none;
  st.wipe();
  st.nonce_out = 1;

  uint8_t nonce[24];

  // -- step 3: transient keypair. [X25519 mult 1] --------------------------
  if (!entropy_fill(g_c_prime, 32))
    return fail(CurveError::no_entropy, st);
  // Clamp. Monocypher clamps internally too, so this is redundant for
  // correctness; doing it here as well means C' and every later scalar
  // multiplication are visibly derived from the same clamped scalar.
  // Clamping is idempotent, so applying it twice is not a hazard.
  g_c_prime[0] &= 248;
  g_c_prime[31] &= 127;
  g_c_prime[31] |= 64;
  crypto_x25519_public_key(g_C_prime, g_c_prime);

  // -- step 4: k_Sc = beforenm(S, c'). [mult 2] ----------------------------
  // Cached because it both seals HELLO and opens WELCOME. Recomputing it
  // would cost a measured ~45 ms for nothing (Appendix C pitfall 3).
  if (!box_beforenm(g_k_Sc, k.server_public, g_c_prime))
    return fail(CurveError::protocol, st); // small-order/invalid server key

  // -- step 5: HELLO (A.2), nonce 1 ----------------------------------------
  memset(g_scratch, 0, HELLO_BODY);
  g_scratch[0] = 5;
  memcpy(g_scratch + 1, "HELLO", 5);
  g_scratch[6] = 1; // CurveZMQ version major
  g_scratch[7] = 0; // ... minor
  // [8,80) stays zero: the anti-amplification padding that makes HELLO as
  // large as WELCOME.
  memcpy(g_scratch + 80, g_C_prime, 32);
  const uint64_t hello_nonce = st.nonce_out++;
  put_u64_be(g_scratch + 112, hello_nonce);
  short_nonce(nonce, NONCE_HELLO, hello_nonce);
  // 64 zero bytes, sealed in place: the plaintext is laid down where the
  // ciphertext will land (out + 16), which secretbox_seal permits.
  memset(g_scratch + 136, 0, 64);
  secretbox_seal(g_scratch + 120, g_scratch + 136, 64, nonce, g_k_Sc);
  if (!send_command(t, g_scratch, HELLO_BODY))
    return fail(CurveError::timeout, st);

  // -- step 6: WELCOME (A.3), exactly 168 bytes ----------------------------
  size_t len = 0;
  if (!recv_command(t, len, timeout_ms))
    return fail(read_failure(t), st);
  if (len != WELCOME_BODY || g_scratch[0] != 7 ||
      memcmp(g_scratch + 1, "WELCOME", 7) != 0)
    return fail(CurveError::welcome, st);
  long_nonce(nonce, NONCE_WELCOME, g_scratch + 8);
  // [24,168) is tag(16) || ciphertext(128); opened in place to [40,168).
  if (!secretbox_open(g_scratch + 40, g_scratch + 24, 128, nonce, g_k_Sc))
    return fail(CurveError::mac, st);
  memcpy(g_S_prime, g_scratch + 40, 32);
  memcpy(g_cookie, g_scratch + 72, 96);

  // -- step 7: the MESSAGE key, beforenm(S', c'). [mult 3] -----------------
  if (!box_beforenm(st.precom, g_S_prime, g_c_prime))
    return fail(CurveError::protocol, st);

  // -- step 8: the vouch box. [mult 4] -------------------------------------
  if (!entropy_fill(g_vouch_tail, 16))
    return fail(CurveError::no_entropy, st);
  if (!box_beforenm(g_k_Spc, g_S_prime, k.client_secret))
    return fail(CurveError::protocol, st);

  // -- step 9: INITIATE (A.4), nonce 2 -------------------------------------
  g_scratch[0] = 8;
  memcpy(g_scratch + 1, "INITIATE", 8);
  memcpy(g_scratch + 9, g_cookie, 96); // echoed verbatim, still opaque to us
  const uint64_t init_nonce = st.nonce_out++;
  put_u64_be(g_scratch + 105, init_nonce);

  // The vouch box occupies [177,257) of the INITIATE plaintext: it is
  // secretbox(C' || S) keyed to (S', c), proving to the broker that whoever
  // holds c also chose C'. Built in place, plaintext at +16 so the seal can
  // alias, before the plaintext around it is written.
  memcpy(g_scratch + 193, g_C_prime, 32);
  memcpy(g_scratch + 225, k.server_public, 32);
  long_nonce(nonce, NONCE_VOUCH, g_vouch_tail);
  secretbox_seal(g_scratch + 177, g_scratch + 193, 64, nonce, g_k_Spc);

  // The rest of the INITIATE plaintext: C || vouch nonce tail || (vouch box)
  // || metadata, starting at 129 = 113 + 16.
  memcpy(g_scratch + 129, k.client_public, 32);
  memcpy(g_scratch + 161, g_vouch_tail, 16);
  const size_t md = zmtp_build_metadata(g_scratch + 257, METADATA_CAP,
                                        socket_type);
  if (md == 0)
    return fail(CurveError::protocol, st);

  short_nonce(nonce, NONCE_INITIATE, init_nonce);
  secretbox_seal(g_scratch + INITIATE_PROLOGUE, g_scratch + 129, 128 + md,
                 nonce, st.precom);
  if (!send_command(t, g_scratch, INITIATE_PROLOGUE + 16 + 128 + md))
    return fail(CurveError::timeout, st);

  // -- step 10: READY, or ERROR (A.5) --------------------------------------
  if (!recv_command(t, len, timeout_ms))
    return fail(read_failure(t), st);
  if (len >= 6 && g_scratch[0] == 5 && memcmp(g_scratch + 1, "ERROR", 5) == 0)
    // The broker rejected us. Overwhelmingly this means our .pub is not in
    // its keys directory, or it was added without restarting the broker.
    // The reason string follows as len(1) || text, deliberately not copied
    // out here -- CurveError::rejected is the actionable part.
    return fail(CurveError::rejected, st);
  if (len < READY_OVERHEAD || g_scratch[0] != 5 ||
      memcmp(g_scratch + 1, "READY", 5) != 0)
    return fail(CurveError::protocol, st);

  const uint64_t ready_nonce = get_u64_be(g_scratch + 6);
  short_nonce(nonce, NONCE_READY, ready_nonce);
  if (!secretbox_open(g_scratch + READY_OVERHEAD, g_scratch + 14,
                      len - READY_OVERHEAD, nonce, st.precom))
    return fail(CurveError::mac, st);

  // The broker's own metadata is discarded: this client already knows what
  // it connected to, and nothing in it changes behaviour.
  st.nonce_in = ready_nonce;
  st.ready = true;

  // Forward secrecy rests on c' being gone once the session key exists.
  wipe_transients();
  return true;
}

} // namespace Mads

#endif // MADS_ENABLE_CURVE
