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
// The MESSAGE one-shot path builds its frame at g_scratch + ZMTP_HDR_MAX and
// writes the outer header into the bytes just before it, so header and body
// leave as one Transport::write(). On this board a write is an SPI
// round-trip to the ESP32 costing ~9 ms, so halving the number of writes
// halves publish latency -- the bytes themselves are almost free.
constexpr size_t SCRATCH_TOTAL = ZMTP_HDR_MAX + SCRATCH_CAP;

// 16-byte nonce prefixes (the trailing 8 bytes are the big-endian counter).
const char NONCE_HELLO[] = "CurveZMQHELLO---";
const char NONCE_INITIATE[] = "CurveZMQINITIATE";
const char NONCE_READY[] = "CurveZMQREADY---";
// 8-byte nonce prefixes (the trailing 16 bytes are random / peer-supplied).
const char NONCE_WELCOME[] = "WELCOME-";
const char NONCE_VOUCH[] = "VOUCH---";
// MESSAGE nonce prefixes are directional (Appendix A.6): the two sides must
// not share a keystream, so board->broker and broker->board differ in their
// last byte.
const char NONCE_MSG_OUT[] = "CurveZMQMESSAGEC"; // board -> broker
const char NONCE_MSG_IN[] = "CurveZMQMESSAGES";  // broker -> board

// "\x07MESSAGE"(8) + short nonce(8) + Poly1305 tag(16). The encrypted flags
// byte that follows makes the flat overhead 33 (Appendix A.6).
constexpr size_t MSG_PROLOGUE = 32;
constexpr size_t MSG_OVERHEAD = MSG_PROLOGUE + 1;

// ---------------------------------------------------------------------------
// Working state. File-static rather than local, per Sec 7.2: these are the
// bytes this code owns, and keeping them off the stack is the part of the
// stack budget that is actually controllable. Together they are ~500 B of
// .bss that a disabled build does not link at all.
// ---------------------------------------------------------------------------
uint8_t g_scratch[SCRATCH_TOTAL];
uint8_t g_c_prime[32];   // c'  transient secret
uint8_t g_C_prime[32];   // C'  transient public
uint8_t g_k_Sc[32];      // beforenm(S,  c')  -- seals HELLO, opens WELCOME
uint8_t g_k_Spc[32];     // beforenm(S', c)   -- seals the vouch box
uint8_t g_S_prime[32];   // S'  server transient public
uint8_t g_cookie[96];
uint8_t g_vouch_tail[16];

/// The two-pass sealer for the blob path. File-static for the reason Sec 7.2
/// gives for every other working buffer: as a local it was ~240 bytes of
/// frame, and because the compiler unions both send paths into one frame,
/// every small JSON publish paid for it too. Measured at 424 B of frame for
/// curve_send() before this moved out, 56 B after. Safe as a single shared
/// instance for the same reason g_scratch is: a send completes inside one
/// call, and the library is single-threaded with one connection in flight.
SecretboxSeal g_seal;

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

// ===========================================================================
// MESSAGE framing (CURVE_PLAN.md Phase 5, Appendix A.6).
//
// These are ZmtpSession members, defined here rather than in
// zmtp_session.cpp so that they sit inside this file's single
// MADS_ENABLE_CURVE guard -- that is what let Phase 5 add the whole
// mechanism without spending a new #ifdef block anywhere (Sec 2).
//
// A MESSAGE is an *ordinary* ZMTP frame: outer flags 0x00, or 0x02 when the
// expanded body exceeds 255. The logical MORE/COMMAND bits travel encrypted,
// as the first plaintext byte. Setting the command bit on the outer frame
// would make the broker read it as a handshake command and drop us
// (Appendix C pitfall 2).
// ===========================================================================

bool ZmtpSession::curve_do_handshake(const char *socket_type,
                                     uint32_t timeout_ms) {
  // The greeting is shared with the NULL path -- only its mechanism field
  // differs, and minor=0 must stay identical for both.
  if (!send_greeting("CURVE")) {
    g_err = CurveError::greeting;
    return false;
  }
  if (!recv_greeting("CURVE", timeout_ms)) {
    // Almost always a broker not running --crypto at all: it offers NULL,
    // we require CURVE, and the mechanism compare fails.
    g_err = CurveError::greeting;
    return false;
  }
  return curve_handshake(_t, *_curve_keys, socket_type, timeout_ms, _curve);
}

bool ZmtpSession::curve_send(const uint8_t *data, size_t len, uint8_t flags) {
  if (!_curve.ready)
    return false;

  const uint64_t n = _curve.nonce_out;
  uint8_t nonce[24];
  short_nonce(nonce, NONCE_MSG_OUT, n);
  // Only the two logical bits travel; LARGE is an outer-frame concern.
  const uint8_t logical = flags & (FLAG_MORE | FLAG_COMMAND);
  const size_t wire = len + MSG_OVERHEAD;

  if (wire <= SCRATCH_CAP) {
    // One-shot path. The handshake is long finished by the time any MESSAGE
    // is sent, so its scratch buffer is free -- reusing it is Sec 7.2's
    // "one static scratch" rule rather than a second buffer. Covers every
    // JSON publish (Agent::PUBLISH_BUF_CAP is 256) and every topic and
    // header frame, halving the Salsa20 work on the common case.
    //
    // The frame is built past the reserved header space so the outer ZMTP
    // header can be written immediately in front of it and the whole thing
    // sent with one write(). Outer flags are 0: LARGE is decided on the
    // *expanded* length (Appendix C pitfall 5).
    uint8_t *o = g_scratch + ZMTP_HDR_MAX;
    o[0] = 7;
    memcpy(o + 1, "MESSAGE", 7);
    put_u64_be(o + 8, n);
    // Lay the plaintext where the ciphertext will land (out + 16) so the
    // seal can work in place.
    o[MSG_PROLOGUE] = logical;
    if (len)
      memcpy(o + MSG_PROLOGUE + 1, data, len);
    secretbox_seal(o + 16, o + MSG_PROLOGUE, len + 1, nonce, _curve.precom);
    uint8_t hdr[ZMTP_HDR_MAX];
    const size_t hlen = zmtp_encode_raw_header(hdr, wire, 0);
    uint8_t *start = o - hlen;
    memcpy(start, hdr, hlen);
    ++_curve.nonce_out;
    return _t.write(start, hlen + wire);
  }

  // The two-pass path streams, so it cannot coalesce; it writes its own
  // outer header first.
  if (!zmtp_write_raw_header(_t, wire, 0))
    return false;

  // Two-pass path, for the blob publish overload. The payload is never
  // copied into a buffer of ours, so RAM does not scale with blob size --
  // which is Phase 5's acceptance criterion. The one-shot branch above did
  // not run, so g_scratch is free: the prologue and the chunk buffer are
  // carved out of it rather than costing either stack or new .bss.
  // CURVE_PLAN.md Phase 5 suggests 64-byte chunks. That was written before
  // anyone had measured a write: at ~9.3 ms per SPI round-trip to the ESP32,
  // 64 bytes means a 16 KB blob costs 256 writes and about 2.4 s. The chunk
  // is a fixed slice of the existing static scratch, so enlarging it does
  // not make RAM scale with blob size -- which is the property Phase 5's
  // acceptance criterion actually protects -- and it cuts the write count
  // fourfold. 256 is what fits after the prologue.
  constexpr size_t CHUNK = 256;
  uint8_t *head = g_scratch + ZMTP_HDR_MAX;
  uint8_t *chunk = head + MSG_PROLOGUE;

  g_seal.init(_curve.precom, nonce);
  g_seal.absorb(&logical, 1);
  g_seal.absorb(data, len);
  head[0] = 7;
  memcpy(head + 1, "MESSAGE", 7);
  put_u64_be(head + 8, n);
  g_seal.tag(head + 16);
  if (!_t.write(head, MSG_PROLOGUE))
    return false;

  g_seal.restart();
  uint8_t enc_flags;
  g_seal.encrypt(&logical, &enc_flags, 1);
  if (!_t.write(&enc_flags, 1))
    return false;
  size_t off = 0;
  while (off < len) {
    const size_t take = (len - off) < CHUNK ? (len - off) : CHUNK;
    g_seal.encrypt(data + off, chunk, take);
    if (!_t.write(chunk, take))
      return false;
    off += take;
  }
  ++_curve.nonce_out;
  return true;
}

bool ZmtpSession::curve_recv_header(uint8_t &flags, uint64_t &len,
                                    uint32_t timeout_ms) {
  if (!_curve.ready)
    return false;

  uint8_t outer;
  uint64_t wire;
  if (!zmtp_read_raw_header(_t, outer, wire, timeout_ms))
    return false;
  if (outer & FLAG_COMMAND)
    return false; // a command frame here is a protocol error post-handshake
  if (wire < MSG_OVERHEAD)
    return false;

  uint8_t pro[MSG_PROLOGUE];
  if (_t.read(pro, sizeof(pro), timeout_ms) != static_cast<int>(sizeof(pro)))
    return false;
  if (pro[0] != 7 || memcmp(pro + 1, "MESSAGE", 7) != 0)
    return false;

  const uint64_t n = get_u64_be(pro + 8);
  // Strictly greater: equal is a replay, lower is a reorder. Either way the
  // frame is refused (Sec 1 non-negotiable 4).
  if (n <= _curve.nonce_in)
    return false;
  // Held, not committed: a forged frame must not be able to ratchet the
  // counter past legitimate ones. curve_end_body() commits it once the tag
  // verifies.
  _rx_nonce_pending = n;

  uint8_t nonce[24];
  short_nonce(nonce, NONCE_MSG_IN, n);
  _rx.init(_curve.precom, nonce, pro + 16);

  // The flags byte is the first plaintext byte. Consuming it here is what
  // lets every caller see a body of pure payload -- CURVE_PLAN.md Phase 5
  // suggests giving poll()'s buffer a spare byte or memmoving the payload
  // down by one, and neither is needed if the prologue absorbs it.
  uint8_t fb;
  if (_t.read(&fb, 1, timeout_ms) != 1)
    return false;
  _rx.update(&fb, &fb, 1);
  flags = fb & (FLAG_MORE | FLAG_COMMAND);

  len = wire - MSG_OVERHEAD;
  _rx_remaining = len;
  return true;
}

bool ZmtpSession::curve_end_body() {
  // The MAC is the only thing that makes any of the plaintext already
  // delivered trustworthy.
  if (!_rx.finish())
    return false;
  _curve.nonce_in = _rx_nonce_pending;
  return true;
}

bool ZmtpSession::curve_recv_body(uint8_t *buf, size_t cap, uint64_t len,
                                  uint32_t timeout_ms) {
  if (len > cap || len != _rx_remaining)
    return false;
  if (len) {
    if (_t.read(buf, static_cast<size_t>(len), timeout_ms) !=
        static_cast<int>(len))
      return false;
    _rx.update(buf, buf, static_cast<size_t>(len)); // decrypts in place
  }
  _rx_remaining = 0;
  return curve_end_body();
}

bool ZmtpSession::curve_skip_body(uint64_t len, uint32_t timeout_ms) {
  if (len != _rx_remaining)
    return false;
  uint8_t scratch[32];
  while (len > 0) {
    const size_t chunk =
        len > sizeof(scratch) ? sizeof(scratch) : static_cast<size_t>(len);
    if (_t.read(scratch, chunk, timeout_ms) != static_cast<int>(chunk))
      return false;
    // Authenticate, then throw the plaintext away. Discarding a frame does
    // not exempt it from its MAC (Sec 1 non-negotiable 5) -- and getting
    // this wrong has no symptom at all until someone attacks you.
    _rx.update(scratch, scratch, chunk);
    len -= chunk;
  }
  _rx_remaining = 0;
  return curve_end_body();
}

bool ZmtpSession::curve_begin_body(uint64_t len) {
  // _rx was already armed by curve_recv_header(); nothing to size up front.
  return len == _rx_remaining;
}

int ZmtpSession::curve_read_chunk(uint8_t *buf, size_t cap,
                                  uint32_t timeout_ms) {
  if (_rx_remaining == 0)
    return 0;
  size_t want = cap;
  if (want > _rx_remaining)
    want = static_cast<size_t>(_rx_remaining);
  const int got = _t.read(buf, want, timeout_ms);
  if (got <= 0)
    return got;
  _rx.update(buf, buf, static_cast<size_t>(got));
  _rx_remaining -= static_cast<uint64_t>(got);
  return got;
}

} // namespace Mads

#endif // MADS_ENABLE_CURVE
