#pragma once
#include "transport.hpp"
#include <cstddef>
#include <cstdint>

namespace Mads {

/**
 * A from-scratch, minimal implementation of just the ZMTP 3.0 wire mechanics
 * MADS needs: the NULL-security handshake and ordinary/subscription frame
 * encoding. Not a general ZMTP library -- no CURVE/PLAIN mechanisms, no
 * ZMTP 3.1 command-based subscriptions, no heartbeating.
 *
 * The handshake deliberately advertises revision=3, minor=0 ("ZMTP/3.0")
 * rather than libzmq's own default of minor=1 ("ZMTP/3.1"). libzmq's
 * zmtp_engine picks its per-connection encoder/decoder from the peer's
 * advertised minor version, so this pins the broker's side of *this*
 * connection to its legacy v2 encoder/decoder, where SUBSCRIBE/CANCEL are
 * ordinary frames with a single 0x01/0x00 prefix byte (see
 * send_subscription()) rather than ZMTP 3.1's command frames -- and sidesteps
 * PING/PONG heartbeating entirely (MADS never enables ZMQ_HEARTBEAT_IVL).
 * All other ordinary-frame encoding is identical between the two minor
 * versions, so this is a safe simplification, not a protocol violation.
 */
class ZmtpCodec {
public:
  // Ordinary ZMTP frame flag bits.
  static constexpr uint8_t FLAG_MORE = 0x01;
  static constexpr uint8_t FLAG_LARGE = 0x02;
  static constexpr uint8_t FLAG_COMMAND = 0x04;

  /**
   * Performs the ZMTP NULL-mechanism handshake over an already-connected
   * transport: sends our 64-byte greeting, reads the peer's, verifies its
   * mechanism is "NULL", exchanges READY command frames advertising
   * `socket_type` ("REQ"/"PUB"/"SUB"), and validates the peer replies READY
   * (not ERROR).
   *
   * @return false on any mismatch, timeout, or disconnection.
   */
  static bool handshake_null(Transport &t, const char *socket_type,
                              uint32_t timeout_ms);

  /// Sends one ordinary ZMTP frame.
  static bool send_frame(Transport &t, const uint8_t *data, size_t len,
                          bool more);
  static bool send_frame(Transport &t, const char *text, bool more);

  /**
   * Reads one ordinary ZMTP frame's header (flags + length). The body must
   * still be read off the stream afterwards via recv_frame_body() or
   * skip_frame_body() regardless of whether the caller wants it -- ZMTP
   * frame boundaries are exact on the byte stream, there is no seeking past
   * an unwanted frame.
   */
  static bool recv_frame_header(Transport &t, uint8_t &flags, uint64_t &len,
                                 uint32_t timeout_ms);

  /// Reads exactly `len` bytes of a frame body into `buf` (`buf_cap` must be >= `len`).
  static bool recv_frame_body(Transport &t, uint8_t *buf, size_t buf_cap,
                              uint64_t len, uint32_t timeout_ms);

  /// Reads and discards `len` bytes of a frame body in small fixed-size chunks.
  static bool skip_frame_body(Transport &t, uint64_t len, uint32_t timeout_ms);

  /**
   * Sends a SUB subscription/unsubscription registration: an ordinary frame
   * `[0x01|0x00][topic bytes]`, per the legacy (minor=0) encoding pinned by
   * handshake_null(). Must be called after a successful SUB handshake.
   */
  static bool send_subscription(Transport &t, const char *topic,
                                 bool subscribe);

private:
  static bool send_greeting(Transport &t);
  static bool recv_greeting(Transport &t, uint32_t timeout_ms);
  static bool send_ready(Transport &t, const char *socket_type);
  static bool recv_ready(Transport &t, uint32_t timeout_ms);

  static bool write_frame_header(Transport &t, uint64_t len, uint8_t flags);
  static bool send_frame_raw(Transport &t, const uint8_t *data, size_t len,
                             uint8_t flags);
};

} // namespace Mads
