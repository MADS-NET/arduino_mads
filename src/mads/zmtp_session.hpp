#pragma once
#include "transport.hpp"
#include <cstddef>
#include <cstdint>

#ifdef MADS_ENABLE_CURVE
#include "curve.hpp"
#endif

namespace Mads {

/**
 * ZMTP frame-header and metadata primitives, as free functions rather than
 * ZmtpSession members.
 *
 * The CURVE handshake (curve.cpp) is a separate translation unit that works
 * directly on a `Transport &` -- it runs before any session state exists to
 * speak through. It needs exactly these three pieces, and duplicating them
 * there would mean two copies of the small/large length encoding and two
 * copies of the Socket-Type property layout, each free to drift. So they
 * live here once and both callers use them.
 *
 * These are the *raw* header primitives: no CURVE MESSAGE prologue, no
 * decryption. ZmtpSession::recv_frame_header() is the logical counterpart
 * that (once Phase 5 lands) hides the 33-byte expansion from callers.
 *
 * They are `inline`, and that is load-bearing rather than stylistic. As
 * ordinary out-of-line functions with external linkage they were emitted as
 * real symbols and called through even when CURVE was compiled out, which
 * cost 88-96 bytes of flash in the disabled build and broke Sec 7.3's
 * "identical to Phase 1, exactly" rule. Inline, the disabled build folds
 * them back into their single call sites and emits nothing extra.
 */
/// Largest ZMTP frame header: 1 flag byte + 8 length bytes.
static constexpr size_t ZMTP_HDR_MAX = 9;

inline size_t zmtp_encode_raw_header(uint8_t *out, uint64_t len, uint8_t flags);
inline bool zmtp_write_raw_header(Transport &t, uint64_t len, uint8_t flags);
inline bool zmtp_read_raw_header(Transport &t, uint8_t &flags, uint64_t &len,
                                 uint32_t timeout_ms);

/// Writes the ZMTP metadata property block -- the single `Socket-Type`
/// property -- and returns its length, or 0 if it would not fit in `cap`.
/// Shared by NULL's READY body and CURVE's INITIATE plaintext, which carry
/// byte-identical metadata.
inline size_t zmtp_build_metadata(uint8_t *out, size_t cap,
                                  const char *socket_type);

/**
 * Owns one connection's ZMTP protocol state -- handshake, frame
 * encoding/decoding -- over a `Transport &`. A prior design used stateless
 * `static` functions instead of an object; once CURVE is enabled
 * (`MADS_ENABLE_CURVE`, guarded inside this class, see zmtp_session.cpp),
 * every connection needs a nonce counter and a precomputed shared key that
 * simply have nowhere to live in a set of `static` functions.
 *
 * With `MADS_ENABLE_CURVE` undefined, this class has no crypto member and
 * every method is a direct, non-branching equivalent of that earlier
 * stateless design -- same instructions, same RAM. See CURVE_PLAN.md Sec 2.
 *
 * A from-scratch, minimal implementation of just the ZMTP 3.0 wire
 * mechanics MADS needs: the NULL-security handshake (and, when enabled,
 * CURVE) plus ordinary/subscription frame encoding. Not a general ZMTP
 * library -- no PLAIN mechanism, no ZMTP 3.1 command-based subscriptions,
 * no heartbeating.
 *
 * The handshake deliberately advertises revision=3, minor=0 ("ZMTP/3.0")
 * rather than libzmq's own default of minor=1 ("ZMTP/3.1"). libzmq's
 * zmtp_engine picks its per-connection encoder/decoder from the peer's
 * advertised minor version, so this pins the broker's side of *this*
 * connection to its legacy v2 encoder/decoder, where SUBSCRIBE/CANCEL are
 * ordinary frames with a single 0x01/0x00 prefix byte (see
 * send_subscription()) rather than ZMTP 3.1's command frames -- and
 * sidesteps PING/PONG heartbeating entirely (MADS never enables
 * ZMQ_HEARTBEAT_IVL). All other ordinary-frame encoding is identical
 * between the two minor versions, so this is a safe simplification, not a
 * protocol violation. It is also load-bearing for CURVE: keeping minor=0
 * is what keeps SUBSCRIBE a plain encrypted MESSAGE body instead of a
 * command frame (CURVE_PLAN.md Appendix A.1).
 */
class ZmtpSession {
public:
  // Ordinary ZMTP frame flag bits.
  static constexpr uint8_t FLAG_MORE = 0x01;
  static constexpr uint8_t FLAG_LARGE = 0x02;
  static constexpr uint8_t FLAG_COMMAND = 0x04;

  /// Longest topic send_subscription() will accept. It assembles
  /// [0x01][topic] into one buffer so the body can be encrypted as a unit
  /// under CURVE, and that buffer has to be bounded somewhere. Comfortably
  /// above Agent::SUB_TOPIC_CAP (24), which is the real limit in practice;
  /// a longer topic fails the call rather than being silently truncated.
  static constexpr size_t MAX_SUBSCRIPTION_TOPIC = 95;

  explicit ZmtpSession(Transport &t) : _t(t) {}

  /// Clears all per-connection protocol state. MUST be called before every
  /// handshake, including reconnects -- see CURVE_PLAN.md Sec 1 non-negotiable
  /// 2 (never reuse a (precom key, nonce) pair). Defined inline: under NULL
  /// there is nothing to clear, and with no cross-TU LTO in the Arduino
  /// build, an out-of-line empty function still costs a real call at every
  /// one of its five call sites -- measured at ~90 bytes flash across
  /// mads_agent.cpp, which is most of what stood between this refactor and
  /// the Phase 1 neutrality budget. Header-inline lets the compiler see
  /// through it at each call site instead.
  /// Under CURVE this wipes the CurveState, which is the whole point of the
  /// rule: a reconnect that kept the old precom key and restarted the nonce
  /// counter would reuse a (key, nonce) pair.
  void reset() { wipe_mechanism(); }

  /**
   * Performs the ZMTP handshake over an already-connected transport: sends
   * our 64-byte greeting, reads the peer's, verifies its mechanism, and
   * completes the mechanism-specific exchange (NULL: READY/READY; CURVE,
   * when enabled: HELLO/WELCOME/INITIATE/READY), advertising `socket_type`
   * ("REQ"/"PUB"/"SUB").
   *
   * @return false on any mismatch, timeout, or disconnection.
   */
  bool handshake(const char *socket_type, uint32_t timeout_ms);

  /// Sends one ordinary ZMTP frame.
  bool send_frame(const uint8_t *data, size_t len, bool more);
  bool send_frame(const char *text, bool more);

  /**
   * Sends a SUB subscription/unsubscription registration: an ordinary frame
   * `[0x01|0x00][topic bytes]`, per the legacy (minor=0) encoding pinned by
   * handshake(). Must be called after a successful SUB handshake.
   */
  bool send_subscription(const char *topic, bool subscribe);

  /**
   * Reads the next frame's *logical* header. Under CURVE (when enabled)
   * this consumes the MESSAGE prologue and `len` is the plaintext length,
   * so callers never see the 33-byte expansion. The session is mid-frame on
   * return: the body MUST be consumed (recv_frame_body / skip_frame_body /
   * the streaming trio) before the next call.
   */
  bool recv_frame_header(uint8_t &flags, uint64_t &len, uint32_t timeout_ms);

  /// Reads exactly `len` bytes of a frame body into `buf` (`buf_cap` must be >= `len`).
  bool recv_frame_body(uint8_t *buf, size_t buf_cap, uint64_t len,
                       uint32_t timeout_ms);

  /// Reads and discards `len` bytes of a frame body. Still authenticates
  /// under CURVE -- a frame we intend to drop is not exempt from the MAC
  /// check (CURVE_PLAN.md Sec 1 non-negotiable 5).
  bool skip_frame_body(uint64_t len, uint32_t timeout_ms);

  /**
   * Streaming body read, for bodies too large to buffer (the settings ini
   * frame). Under CURVE the plaintext is delivered before it is
   * authenticated, so a caller MUST discard everything it derived from the
   * chunks if end_recv_body() returns false.
   *
   * The caller is responsible for tracking how many body bytes remain and
   * sizing each read_body_chunk() request accordingly (never requesting
   * more than remains) -- the session does not duplicate that count under
   * NULL. `len` passed to begin_recv_body() is unused there; it exists so
   * CURVE can size its keystream/MAC state up front.
   *
   * Defined inline for the same reason as reset(): under NULL each of
   * these is a one-line pass-through, and header-inlining them lets the
   * (LTO-less) Arduino build fold them into fetch_settings() instead of
   * paying three real cross-TU calls for functions that do nothing beyond
   * forwarding to Transport::read(). (CURVE, when enabled, gives these
   * real bodies -- SecretboxOpen state -- and they move out of line then.)
   */
  bool begin_recv_body(uint64_t len) {
    return curve_active() ? curve_begin_body(len) : true;
  }
  int read_body_chunk(uint8_t *buf, size_t cap, uint32_t timeout_ms) {
    return curve_active() ? curve_read_chunk(buf, cap, timeout_ms)
                          : _t.read(buf, cap, timeout_ms);
  }
  bool end_recv_body() { return curve_active() ? curve_end_body() : true; }

private:
  // The greeting's mechanism field: 20 zero-padded octets at offset 12.
  // CURVE_PLAN.md Appendix A.1 tabulates it as 16 bytes, which is a slip in
  // the plan rather than a difference on the wire -- bytes 28-31 are zero
  // under either reading, and `as-server` is at 32 in both, so the emitted
  // and accepted bytes are identical. 20 is what ZMTP 3.0 and libzmq say.
  static constexpr size_t MECHANISM_OFF = 12;
  static constexpr size_t MECHANISM_LEN = 20;

  // The mechanism name is the only part of the greeting that differs
  // between NULL and CURVE; `minor` stays 0 for both, and is load-bearing
  // for CURVE (see the class comment above).
  //
  // Defined inline for the same footprint reason as reset() and the
  // streaming trio: each has exactly one call site, and out of line the
  // mechanism stays an opaque runtime pointer, so strlen/memcpy against a
  // string literal cannot fold. That cost ~40 bytes of flash in the
  // *disabled* build, which Sec 7.3 does not allow. Inlined, "NULL" folds
  // to the same constant stores Phase 1 emitted.
  bool send_greeting(const char *mechanism) {
    uint8_t greeting[64] = {0};
    greeting[0] = 0xFF;  // signature start
    // bytes 1-8: signature padding, zero is a valid "not significant" value
    greeting[9] = 0x7F;  // signature end (marks a "versioned peer")
    greeting[10] = 3;    // revision (major) = 3
    greeting[11] = 0;    // minor = 0 -- see class doc: pins the peer's
                         // per-connection encoder to the legacy
                         // single-byte-prefixed subscribe encoding and
                         // avoids heartbeating.
    const size_t mlen = __builtin_strlen(mechanism);
    if (mlen > MECHANISM_LEN)
      return false;
    __builtin_memcpy(greeting + MECHANISM_OFF, mechanism, mlen);
    // remainder of the mechanism field stays zero-padded
    greeting[32] = 0;    // as-server = false
    // bytes 33-63: filler, zero
    return _t.write(greeting, sizeof(greeting));
  }

  bool recv_greeting(const char *mechanism, uint32_t timeout_ms) {
    uint8_t greeting[64];
    if (_t.read(greeting, sizeof(greeting), timeout_ms) != sizeof(greeting))
      return false;
    if (greeting[0] != 0xFF || greeting[9] != 0x7F)
      return false;
    if (greeting[10] != 3)
      return false; // require ZMTP major revision 3
    // Only the name bytes are compared, not the whole zero-padded field.
    // libzmq compares all 20, which is stricter -- it rejects a peer
    // advertising "NULLX" where this accepts it. Matching libzmq costs flash
    // in the disabled build, which Sec 7.3 requires to stay byte-identical
    // to Phase 1, so the stricter compare cannot be introduced without
    // breaking a stated acceptance criterion. Recorded rather than silent;
    // no known peer advertises a mechanism name with a matching prefix.
    const size_t mlen = __builtin_strlen(mechanism);
    if (mlen > MECHANISM_LEN)
      return false;
    if (__builtin_memcmp(greeting + MECHANISM_OFF, mechanism, mlen) != 0)
      return false; // peer requires a different security mechanism
    return true;
  }
  bool send_ready(const char *socket_type);
  bool recv_ready(uint32_t timeout_ms);

  bool write_frame_header(uint64_t len, uint8_t flags);
  bool send_frame_raw(const uint8_t *data, size_t len, uint8_t flags);

  // -------------------------------------------------------------------
  // The mechanism seam (CURVE_PLAN.md Sec 2). Every CURVE-specific member
  // is declared here and stubbed in the #else, so the rest of this class
  // and all of zmtp_session.cpp can branch on plain `if (curve_active())`
  // with no #ifdef of their own. Under NULL curve_active() is a constexpr
  // false, so each of those branches folds away entirely and the stubs are
  // never called or emitted -- which is what keeps the disabled build's
  // codegen identical. Phase 5 added seven hooks here and needed *no* new
  // guard block anywhere; if a future phase cannot manage that, Sec 2 says
  // the seam has drifted.
  // -------------------------------------------------------------------
#ifdef MADS_ENABLE_CURVE
public:
  /// Arms this session for CURVE. `k` must outlive the session and stay
  /// valid across reconnects (the Agent owns it). Passing nullptr, or never
  /// calling this, leaves the session on the NULL mechanism.
  void set_curve_keys(const CurveKeys *k) { _curve_keys = k; }
  /// Read-only view of the armed state -- exists so a caller can assert
  /// nonce_out == 3 after a fresh handshake (CURVE_PLAN.md Phase 8 step 5).
  const CurveState &curve_state() const { return _curve; }

private:
  bool curve_active() const { return _curve_keys != nullptr; }
  void wipe_mechanism() {
    _curve.wipe();
    _rx_remaining = 0;
    _rx_nonce_pending = 0;
  }
  // Defined in curve.cpp, inside that file's own guard, so they cost no
  // further #ifdef here.
  bool curve_do_handshake(const char *socket_type, uint32_t timeout_ms);
  bool curve_send(const uint8_t *data, size_t len, uint8_t flags);
  bool curve_recv_header(uint8_t &flags, uint64_t &len, uint32_t timeout_ms);
  bool curve_recv_body(uint8_t *buf, size_t cap, uint64_t len,
                       uint32_t timeout_ms);
  bool curve_skip_body(uint64_t len, uint32_t timeout_ms);
  bool curve_begin_body(uint64_t len);
  int curve_read_chunk(uint8_t *buf, size_t cap, uint32_t timeout_ms);
  bool curve_end_body();

  const CurveKeys *_curve_keys = nullptr;
  CurveState _curve{};
  /// Receive state for the frame currently being read. `_rx` is per-session
  /// rather than shared because a session can sit mid-frame between calls
  /// (recv_frame_header now, body later), and the Agent has two sessions.
  SecretboxOpen _rx;
  uint64_t _rx_remaining = 0;
  /// The nonce of the frame being read, committed to _curve.nonce_in only
  /// once its tag verifies. Committing at header time would let a forged
  /// frame ratchet the counter past legitimate ones.
  uint64_t _rx_nonce_pending = 0;
#else
  static constexpr bool curve_active() { return false; }
  void wipe_mechanism() {}
  bool curve_do_handshake(const char *, uint32_t) { return false; }
  bool curve_send(const uint8_t *, size_t, uint8_t) { return false; }
  bool curve_recv_header(uint8_t &, uint64_t &, uint32_t) { return false; }
  bool curve_recv_body(uint8_t *, size_t, uint64_t, uint32_t) { return false; }
  bool curve_skip_body(uint64_t, uint32_t) { return false; }
  bool curve_begin_body(uint64_t) { return false; }
  int curve_read_chunk(uint8_t *, size_t, uint32_t) { return -1; }
  bool curve_end_body() { return false; }
#endif

  Transport &_t;
  // NULL-mechanism state: none. begin_recv_body/read_body_chunk/
  // end_recv_body need no state of their own here -- the caller already
  // tracks how many body bytes remain (it must, to size each chunk read),
  // so read_body_chunk() just bounds-checks and forwards to _t.read().
  // (CURVE, when enabled, adds a SecretboxOpen member here, guarded -- see
  // zmtp_session.cpp -- which is exactly why this trio exists as an API
  // instead of callers reading the transport directly.)
};

// ---------------------------------------------------------------------------
// Inline definitions. After the class because they use ZmtpSession's flag
// constants; see the declarations above for why they are inline at all.
// ---------------------------------------------------------------------------
/// Serialises a frame header into `out` (which must have room for
/// ZMTP_HDR_MAX) and returns its length. Split out from the write so a
/// caller that already holds the whole frame in a buffer can prepend the
/// header and issue a single Transport::write(). On the UNO R4 WiFi each
/// write is an SPI round-trip to the ESP32 costing ~9 ms, so the number of
/// write() calls, not the number of bytes, is what sets publish latency.
inline size_t zmtp_encode_raw_header(uint8_t *out, uint64_t len,
                                     uint8_t flags) {
  if (len > 255) {
    out[0] = static_cast<uint8_t>(flags | ZmtpSession::FLAG_LARGE);
    for (int i = 0; i < 8; ++i)
      out[1 + i] = static_cast<uint8_t>((len >> (8 * (7 - i))) & 0xFF);
    return 9;
  }
  out[0] = flags;
  out[1] = static_cast<uint8_t>(len);
  return 2;
}

inline bool zmtp_write_raw_header(Transport &t, uint64_t len, uint8_t flags) {
  uint8_t header[ZMTP_HDR_MAX];
  const size_t hlen = zmtp_encode_raw_header(header, len, flags);
  return t.write(header, hlen);
}

inline bool zmtp_read_raw_header(Transport &t, uint8_t &flags, uint64_t &len,
                                 uint32_t timeout_ms) {
  uint8_t b;
  if (t.read(&b, 1, timeout_ms) != 1)
    return false;
  flags = b;
  if (flags & ZmtpSession::FLAG_LARGE) {
    uint8_t lb[8];
    if (t.read(lb, 8, timeout_ms) != 8)
      return false;
    uint64_t l = 0;
    for (int i = 0; i < 8; ++i)
      l = (l << 8) | lb[i];
    len = l;
  } else {
    uint8_t lb;
    if (t.read(&lb, 1, timeout_ms) != 1)
      return false;
    len = lb;
  }
  return true;
}

inline size_t zmtp_build_metadata(uint8_t *out, size_t cap,
                                  const char *socket_type) {
  const char name[] = "Socket-Type";
  const uint8_t name_len = static_cast<uint8_t>(sizeof(name) - 1);
  const uint32_t value_len = static_cast<uint32_t>(__builtin_strlen(socket_type));
  const size_t total = 1u + name_len + 4u + value_len;
  if (total > cap)
    return 0;

  size_t pos = 0;
  out[pos++] = name_len;
  __builtin_memcpy(out + pos, name, name_len);
  pos += name_len;
  // Property values are length-prefixed big-endian uint32.
  out[pos++] = static_cast<uint8_t>((value_len >> 24) & 0xFF);
  out[pos++] = static_cast<uint8_t>((value_len >> 16) & 0xFF);
  out[pos++] = static_cast<uint8_t>((value_len >> 8) & 0xFF);
  out[pos++] = static_cast<uint8_t>(value_len & 0xFF);
  __builtin_memcpy(out + pos, socket_type, value_len);
  pos += value_len;
  return pos;
}

} // namespace Mads
