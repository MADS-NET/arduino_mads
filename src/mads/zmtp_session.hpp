#pragma once
#include "transport.hpp"
#include <cstddef>
#include <cstdint>

namespace Mads {

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
  /// (A CurveState member and its zeroisation are added here in Phase 4/5,
  /// out of this pass's scope -- not present yet.)
  void reset() {}

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
  bool begin_recv_body(uint64_t /*len*/) { return true; }
  int read_body_chunk(uint8_t *buf, size_t cap, uint32_t timeout_ms) {
    return _t.read(buf, cap, timeout_ms);
  }
  bool end_recv_body() { return true; }

private:
  bool send_greeting();
  bool recv_greeting(uint32_t timeout_ms);
  bool send_ready(const char *socket_type);
  bool recv_ready(uint32_t timeout_ms);

  bool write_frame_header(uint64_t len, uint8_t flags);
  bool send_frame_raw(const uint8_t *data, size_t len, uint8_t flags);

  Transport &_t;
  // NULL-mechanism state: none. begin_recv_body/read_body_chunk/
  // end_recv_body need no state of their own here -- the caller already
  // tracks how many body bytes remain (it must, to size each chunk read),
  // so read_body_chunk() just bounds-checks and forwards to _t.read().
  // (CURVE, when enabled, adds a SecretboxOpen member here, guarded -- see
  // zmtp_session.cpp -- which is exactly why this trio exists as an API
  // instead of callers reading the transport directly.)
};

} // namespace Mads
