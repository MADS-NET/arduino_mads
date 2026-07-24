#include "zmtp_codec.hpp"
#include <cstring>

namespace Mads {

bool ZmtpCodec::send_greeting(Transport &t) {
  uint8_t greeting[64] = {0};
  greeting[0] = 0xFF;            // signature start
  // bytes 1-8: signature padding, zero is a valid "not significant" value
  greeting[9] = 0x7F;             // signature end (marks a "versioned peer")
  greeting[10] = 3;               // revision (major) = 3
  greeting[11] = 0;               // minor = 0 -- see class doc: pins the
                                   // peer's per-connection encoder to the
                                   // legacy single-byte-prefixed subscribe
                                   // encoding and avoids heartbeating.
  greeting[12] = 'N';
  greeting[13] = 'U';
  greeting[14] = 'L';
  greeting[15] = 'L';
  // bytes 16-31: mechanism padding, zero
  greeting[32] = 0;                // as-server = false
  // bytes 33-63: filler, zero
  return t.write(greeting, sizeof(greeting));
}

bool ZmtpCodec::recv_greeting(Transport &t, uint32_t timeout_ms) {
  uint8_t greeting[64];
  if (t.read(greeting, sizeof(greeting), timeout_ms) != sizeof(greeting))
    return false;
  if (greeting[0] != 0xFF || greeting[9] != 0x7F)
    return false;
  if (greeting[10] != 3)
    return false; // require ZMTP major revision 3
  if (greeting[12] != 'N' || greeting[13] != 'U' || greeting[14] != 'L' ||
      greeting[15] != 'L')
    return false; // peer requires CURVE/PLAIN, unsupported here
  return true;
}

bool ZmtpCodec::write_frame_header(Transport &t, uint64_t len, uint8_t flags) {
  uint8_t header[9];
  size_t hlen;
  if (len > 255) {
    header[0] = static_cast<uint8_t>(flags | FLAG_LARGE);
    for (int i = 0; i < 8; ++i)
      header[1 + i] = static_cast<uint8_t>((len >> (8 * (7 - i))) & 0xFF);
    hlen = 9;
  } else {
    header[0] = flags;
    header[1] = static_cast<uint8_t>(len);
    hlen = 2;
  }
  return t.write(header, hlen);
}

bool ZmtpCodec::send_frame_raw(Transport &t, const uint8_t *data, size_t len,
                               uint8_t flags) {
  if (!write_frame_header(t, len, flags))
    return false;
  if (len == 0)
    return true;
  return t.write(data, len);
}

bool ZmtpCodec::send_frame(Transport &t, const uint8_t *data, size_t len,
                           bool more) {
  return send_frame_raw(t, data, len, more ? FLAG_MORE : 0);
}

bool ZmtpCodec::send_frame(Transport &t, const char *text, bool more) {
  return send_frame(t, reinterpret_cast<const uint8_t *>(text),
                     strlen(text), more);
}

bool ZmtpCodec::recv_frame_header(Transport &t, uint8_t &flags, uint64_t &len,
                                  uint32_t timeout_ms) {
  uint8_t b;
  if (t.read(&b, 1, timeout_ms) != 1)
    return false;
  flags = b;
  if (flags & FLAG_LARGE) {
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

bool ZmtpCodec::recv_frame_body(Transport &t, uint8_t *buf, size_t buf_cap,
                                uint64_t len, uint32_t timeout_ms) {
  if (len > buf_cap)
    return false;
  if (len == 0)
    return true;
  return t.read(buf, static_cast<size_t>(len), timeout_ms) ==
         static_cast<int>(len);
}

bool ZmtpCodec::skip_frame_body(Transport &t, uint64_t len,
                                uint32_t timeout_ms) {
  uint8_t scratch[32];
  while (len > 0) {
    size_t chunk = len > sizeof(scratch) ? sizeof(scratch)
                                          : static_cast<size_t>(len);
    if (t.read(scratch, chunk, timeout_ms) != static_cast<int>(chunk))
      return false;
    len -= chunk;
  }
  return true;
}

bool ZmtpCodec::send_ready(Transport &t, const char *socket_type) {
  uint8_t body[32];
  size_t pos = 0;
  body[pos++] = 5;
  body[pos++] = 'R';
  body[pos++] = 'E';
  body[pos++] = 'A';
  body[pos++] = 'D';
  body[pos++] = 'Y';

  const char name[] = "Socket-Type";
  uint8_t name_len = static_cast<uint8_t>(sizeof(name) - 1);
  body[pos++] = name_len;
  memcpy(body + pos, name, name_len);
  pos += name_len;

  uint32_t value_len = static_cast<uint32_t>(strlen(socket_type));
  body[pos++] = static_cast<uint8_t>((value_len >> 24) & 0xFF);
  body[pos++] = static_cast<uint8_t>((value_len >> 16) & 0xFF);
  body[pos++] = static_cast<uint8_t>((value_len >> 8) & 0xFF);
  body[pos++] = static_cast<uint8_t>(value_len & 0xFF);
  memcpy(body + pos, socket_type, value_len);
  pos += value_len;

  return send_frame_raw(t, body, pos, FLAG_COMMAND);
}

bool ZmtpCodec::recv_ready(Transport &t, uint32_t timeout_ms) {
  uint8_t flags;
  uint64_t len;
  if (!recv_frame_header(t, flags, len, timeout_ms))
    return false;
  if (!(flags & FLAG_COMMAND))
    return false; // must be a command frame (READY or ERROR)
  if (len < 6)
    return false;

  uint8_t head[6];
  if (!recv_frame_body(t, head, sizeof(head), 6, timeout_ms))
    return false;
  bool is_ready = head[0] == 5 && head[1] == 'R' && head[2] == 'E' &&
                  head[3] == 'A' && head[4] == 'D' && head[5] == 'Y';

  // Whether it's READY or ERROR, drain the remaining property/reason bytes:
  // ZMTP frame boundaries are exact on the stream, they can't be skipped.
  if (!skip_frame_body(t, len - 6, timeout_ms))
    return false;

  return is_ready;
}

bool ZmtpCodec::handshake_null(Transport &t, const char *socket_type,
                               uint32_t timeout_ms) {
  if (!send_greeting(t))
    return false;
  if (!recv_greeting(t, timeout_ms))
    return false;
  if (!send_ready(t, socket_type))
    return false;
  if (!recv_ready(t, timeout_ms))
    return false;
  return true;
}

bool ZmtpCodec::send_subscription(Transport &t, const char *topic,
                                  bool subscribe) {
  size_t topic_len = strlen(topic);
  uint8_t prefix = subscribe ? 0x01 : 0x00;
  if (!write_frame_header(t, topic_len + 1, 0))
    return false;
  if (!t.write(&prefix, 1))
    return false;
  if (topic_len == 0)
    return true;
  return t.write(reinterpret_cast<const uint8_t *>(topic), topic_len);
}

} // namespace Mads
