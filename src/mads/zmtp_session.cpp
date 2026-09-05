#include "zmtp_session.hpp"
#include <cstring>

namespace Mads {

bool ZmtpSession::write_frame_header(uint64_t len, uint8_t flags) {
  return zmtp_write_raw_header(_t, len, flags);
}

bool ZmtpSession::send_frame_raw(const uint8_t *data, size_t len,
                                  uint8_t flags) {
  if (curve_active())
    return curve_send(data, len, flags);
  if (!write_frame_header(len, flags))
    return false;
  if (len == 0)
    return true;
  return _t.write(data, len);
}

bool ZmtpSession::send_frame(const uint8_t *data, size_t len, bool more) {
  return send_frame_raw(data, len, more ? FLAG_MORE : 0);
}

bool ZmtpSession::send_frame(const char *text, bool more) {
  return send_frame(reinterpret_cast<const uint8_t *>(text), strlen(text),
                     more);
}

bool ZmtpSession::recv_frame_header(uint8_t &flags, uint64_t &len,
                                     uint32_t timeout_ms) {
  // Under CURVE this consumes the MESSAGE prologue and reports the plaintext
  // length, so callers never see the 33-byte expansion.
  if (curve_active())
    return curve_recv_header(flags, len, timeout_ms);
  return zmtp_read_raw_header(_t, flags, len, timeout_ms);
}

bool ZmtpSession::recv_frame_body(uint8_t *buf, size_t buf_cap, uint64_t len,
                                   uint32_t timeout_ms) {
  if (curve_active())
    return curve_recv_body(buf, buf_cap, len, timeout_ms);
  if (len > buf_cap)
    return false;
  if (len == 0)
    return true;
  return _t.read(buf, static_cast<size_t>(len), timeout_ms) ==
         static_cast<int>(len);
}

bool ZmtpSession::skip_frame_body(uint64_t len, uint32_t timeout_ms) {
  // Under CURVE this still authenticates: discarding the plaintext does not
  // exempt a frame from its MAC (Sec 1 non-negotiable 5).
  if (curve_active())
    return curve_skip_body(len, timeout_ms);
  uint8_t scratch[32];
  while (len > 0) {
    size_t chunk =
        len > sizeof(scratch) ? sizeof(scratch) : static_cast<size_t>(len);
    if (_t.read(scratch, chunk, timeout_ms) != static_cast<int>(chunk))
      return false;
    len -= chunk;
  }
  return true;
}

bool ZmtpSession::send_ready(const char *socket_type) {
  uint8_t body[32];
  size_t pos = 0;
  body[pos++] = 5;
  body[pos++] = 'R';
  body[pos++] = 'E';
  body[pos++] = 'A';
  body[pos++] = 'D';
  body[pos++] = 'Y';

  // Identical property bytes to CURVE's INITIATE metadata -- one builder.
  const size_t md = zmtp_build_metadata(body + pos, sizeof(body) - pos,
                                        socket_type);
  if (md == 0)
    return false;
  pos += md;

  return send_frame_raw(body, pos, FLAG_COMMAND);
}

bool ZmtpSession::recv_ready(uint32_t timeout_ms) {
  uint8_t flags;
  uint64_t len;
  if (!recv_frame_header(flags, len, timeout_ms))
    return false;
  if (!(flags & FLAG_COMMAND))
    return false; // must be a command frame (READY or ERROR)
  if (len < 6)
    return false;

  uint8_t head[6];
  if (!recv_frame_body(head, sizeof(head), 6, timeout_ms))
    return false;
  bool is_ready = head[0] == 5 && head[1] == 'R' && head[2] == 'E' &&
                  head[3] == 'A' && head[4] == 'D' && head[5] == 'Y';

  // Whether it's READY or ERROR, drain the remaining property/reason bytes:
  // ZMTP frame boundaries are exact on the stream, they can't be skipped.
  if (!skip_frame_body(len - 6, timeout_ms))
    return false;

  return is_ready;
}

bool ZmtpSession::handshake(const char *socket_type, uint32_t timeout_ms) {
  // The mechanism branch (DEVELOPER.md, the mechanism seam). Under NULL curve_active() is
  // a constexpr false and this whole arm folds away; see the seam block in
  // the header for why it needs no #ifdef here.
  if (curve_active())
    return curve_do_handshake(socket_type, timeout_ms);
  if (!send_greeting("NULL"))
    return false;
  if (!recv_greeting("NULL", timeout_ms))
    return false;
  if (!send_ready(socket_type))
    return false;
  if (!recv_ready(timeout_ms))
    return false;
  return true;
}

bool ZmtpSession::send_subscription(const char *topic, bool subscribe) {
  // The body is [0x01|0x00][topic], which is exactly what the broker's
  // downgraded (minor=0) decoder expects to find -- under CURVE it expects
  // to find it *inside the ciphertext*, so this has to be assembled and
  // handed to send_frame_raw() rather than written straight to the
  // transport as it used to be. DEVELOPER.md says subscriptions
  // need no special handling, which is true of their content and not of
  // their framing.
  const size_t topic_len = strlen(topic);
  uint8_t body[1 + MAX_SUBSCRIPTION_TOPIC];
  if (topic_len + 1 > sizeof(body))
    return false;
  body[0] = subscribe ? 0x01 : 0x00;
  memcpy(body + 1, topic, topic_len);
  return send_frame_raw(body, topic_len + 1, 0);
}

} // namespace Mads
