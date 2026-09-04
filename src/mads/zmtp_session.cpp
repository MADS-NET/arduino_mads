#include "zmtp_session.hpp"
#include <cstring>

namespace Mads {

bool ZmtpSession::write_frame_header(uint64_t len, uint8_t flags) {
  return zmtp_write_raw_header(_t, len, flags);
}

bool ZmtpSession::send_frame_raw(const uint8_t *data, size_t len,
                                  uint8_t flags) {
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
  // Phase 5 gives this a CURVE branch that consumes the MESSAGE prologue and
  // reports the plaintext length; today both mechanisms read the raw header.
  return zmtp_read_raw_header(_t, flags, len, timeout_ms);
}

bool ZmtpSession::recv_frame_body(uint8_t *buf, size_t buf_cap, uint64_t len,
                                   uint32_t timeout_ms) {
  if (len > buf_cap)
    return false;
  if (len == 0)
    return true;
  return _t.read(buf, static_cast<size_t>(len), timeout_ms) ==
         static_cast<int>(len);
}

bool ZmtpSession::skip_frame_body(uint64_t len, uint32_t timeout_ms) {
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
#ifdef MADS_ENABLE_CURVE
  // The one mechanism branch in the library (CURVE_PLAN.md Sec 2). The
  // greeting is shared: only its mechanism field differs, and `minor = 0`
  // has to stay identical for both, so it is not duplicated into curve.cpp.
  if (_curve_keys) {
    if (!send_greeting("CURVE")) {
      curve_note_error(CurveError::greeting);
      return false;
    }
    if (!recv_greeting("CURVE", timeout_ms)) {
      // Almost always a broker that is not running --crypto at all: it
      // offers NULL, we require CURVE, and the mechanism compare fails.
      curve_note_error(CurveError::greeting);
      return false;
    }
    return curve_handshake(_t, *_curve_keys, socket_type, timeout_ms, _curve);
  }
#endif
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
  size_t topic_len = strlen(topic);
  uint8_t prefix = subscribe ? 0x01 : 0x00;
  if (!write_frame_header(topic_len + 1, 0))
    return false;
  if (!_t.write(&prefix, 1))
    return false;
  if (topic_len == 0)
    return true;
  return _t.write(reinterpret_cast<const uint8_t *>(topic), topic_len);
}

} // namespace Mads
