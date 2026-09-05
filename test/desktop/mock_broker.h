#pragma once
// A scripted CurveZMQ peer over the Transport interface, shared by
// test_curve_golden.cpp and test_curve_message.cpp.
//
// It really performs the server side: it seals a genuine WELCOME and READY
// that the client must open, and it encrypts and decrypts MESSAGE frames
// with the correct *opposite* directional nonce prefix. That last part is
// what makes the MESSAGE tests meaningful -- a client tested only against
// itself would pass even if both directions used the same prefix, which
// would be a real interoperability bug against a live broker.
//
// std::vector is fine here: the no-allocation rule (DEVELOPER.md, CURVE invariants
// non-negotiable 9) governs the library, not desktop test scaffolding.
#include "crypto/monocypher.h"
#include "crypto/nacl_box.h"
#include "transport.hpp"
#include "zmtp_session.hpp"

#include <cstring>
#include <vector>

// Test keys, not secrets: they exist only to make the peer reproducible.
// Secrets are given, publics are derived, so a typo cannot produce a
// self-consistent but wrong fixture.
static const uint8_t BROKER_SECRET[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
static const uint8_t BROKER_TRANSIENT_SECRET[32] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
    0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
    0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf};
static const uint8_t CLIENT_SECRET[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
static const uint8_t WELCOME_LONG_NONCE[16] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

inline void mb_put_u64_be(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; ++i)
    p[i] = static_cast<uint8_t>((v >> (8 * (7 - i))) & 0xFF);
}
inline uint64_t mb_get_u64_be(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i)
    v = (v << 8) | p[i];
  return v;
}

class MockBroker : public Mads::Transport {
public:
  std::vector<uint8_t> hello, initiate;
  /// Raw bytes the client wrote after the handshake completed -- MESSAGE
  /// frames, still encrypted, for the test to decode.
  std::vector<uint8_t> rx_raw;

  MockBroker() {
    crypto_x25519_public_key(_S, BROKER_SECRET);
    crypto_x25519_public_key(_Sp, BROKER_TRANSIENT_SECRET);
    for (int i = 0; i < 96; ++i)
      _cookie[i] = static_cast<uint8_t>(0x40 + i); // opaque to the client
  }
  const uint8_t *server_public() const { return _S; }
  const uint8_t *precom() const { return _precom; }
  bool handshake_done() const { return _done; }

  bool connect(const char *, uint16_t) override { return true; }
  bool connected() override { return true; }
  void close() override {}
  bool available() override { return !_out.empty(); }

  bool write(const uint8_t *data, size_t len) override {
    if (_done) {
      rx_raw.insert(rx_raw.end(), data, data + len);
      return true;
    }
    _in.insert(_in.end(), data, data + len);
    advance();
    return true;
  }

  int read(uint8_t *buf, size_t len, uint32_t) override {
    size_t n = _out.size() < len ? _out.size() : len;
    std::memcpy(buf, _out.data(), n);
    _out.erase(_out.begin(), _out.begin() + n);
    return static_cast<int>(n);
  }

  /// Encodes one MESSAGE the way a broker would -- note the "...S" prefix,
  /// the opposite direction from the client's "...C" -- and queues it.
  /// Returns the encoded frame so a test can tamper with it first.
  std::vector<uint8_t> encode_message(uint8_t logical_flags,
                                      const uint8_t *payload, size_t len,
                                      uint64_t nonce_value) {
    uint8_t nonce[24];
    std::memcpy(nonce, "CurveZMQMESSAGES", 16);
    mb_put_u64_be(nonce + 16, nonce_value);

    std::vector<uint8_t> pt(1 + len);
    pt[0] = logical_flags;
    if (len)
      std::memcpy(pt.data() + 1, payload, len);

    std::vector<uint8_t> body(32 + 1 + len);
    body[0] = 7;
    std::memcpy(body.data() + 1, "MESSAGE", 7);
    mb_put_u64_be(body.data() + 8, nonce_value);
    Mads::secretbox_seal(body.data() + 16, pt.data(), pt.size(), nonce,
                         _precom);

    std::vector<uint8_t> frame;
    const size_t wire = body.size();
    if (wire > 255) {
      frame.push_back(Mads::ZmtpSession::FLAG_LARGE);
      uint8_t l[8];
      mb_put_u64_be(l, wire);
      frame.insert(frame.end(), l, l + 8);
    } else {
      frame.push_back(0);
      frame.push_back(static_cast<uint8_t>(wire));
    }
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
  }

  void queue(const std::vector<uint8_t> &frame) {
    _out.insert(_out.end(), frame.begin(), frame.end());
  }
  uint64_t next_out_nonce() { return _out_nonce++; }

  /// Decodes one client MESSAGE from rx_raw at `off`, advancing it.
  /// Returns false if the frame is malformed or fails its MAC.
  bool decode_message(size_t &off, uint8_t &logical_flags,
                      std::vector<uint8_t> &payload, uint64_t &nonce_value,
                      bool &was_large) {
    if (off + 2 > rx_raw.size())
      return false;
    const uint8_t outer = rx_raw[off];
    size_t hdr, wire;
    if (outer & Mads::ZmtpSession::FLAG_LARGE) {
      if (off + 9 > rx_raw.size())
        return false;
      wire = static_cast<size_t>(mb_get_u64_be(&rx_raw[off + 1]));
      hdr = 9;
      was_large = true;
    } else {
      wire = rx_raw[off + 1];
      hdr = 2;
      was_large = false;
    }
    if (outer & Mads::ZmtpSession::FLAG_COMMAND)
      return false; // MESSAGE must be an ordinary frame
    if (off + hdr + wire > rx_raw.size() || wire < 33)
      return false;
    const uint8_t *body = &rx_raw[off + hdr];
    if (body[0] != 7 || std::memcmp(body + 1, "MESSAGE", 7) != 0)
      return false;
    nonce_value = mb_get_u64_be(body + 8);

    uint8_t nonce[24];
    std::memcpy(nonce, "CurveZMQMESSAGEC", 16); // client -> broker
    mb_put_u64_be(nonce + 16, nonce_value);

    const size_t ptlen = wire - 32;
    std::vector<uint8_t> pt(ptlen);
    if (!Mads::secretbox_open(pt.data(), body + 16, ptlen, nonce, _precom))
      return false;
    logical_flags = pt[0];
    payload.assign(pt.begin() + 1, pt.end());
    off += hdr + wire;
    return true;
  }

private:
  std::vector<uint8_t> _in, _out;
  bool _greeted = false, _done = false;
  uint8_t _S[32], _Sp[32], _cookie[96], _Cp[32] = {0}, _precom[32] = {0};
  // READY consumed the broker's nonce 1, so MESSAGEs start at 2.
  uint64_t _out_nonce = 2;

  void push_frame(const uint8_t *body, size_t len) {
    if (len > 255) {
      _out.push_back(Mads::ZmtpSession::FLAG_COMMAND |
                     Mads::ZmtpSession::FLAG_LARGE);
      uint8_t l[8];
      mb_put_u64_be(l, len);
      _out.insert(_out.end(), l, l + 8);
    } else {
      _out.push_back(Mads::ZmtpSession::FLAG_COMMAND);
      _out.push_back(static_cast<uint8_t>(len));
    }
    _out.insert(_out.end(), body, body + len);
  }

  void push_greeting() {
    uint8_t g[64] = {0};
    g[0] = 0xFF;
    g[9] = 0x7F;
    g[10] = 3;
    g[11] = 0;
    std::memcpy(g + 12, "CURVE", 5);
    g[32] = 1; // as-server
    _out.insert(_out.end(), g, g + 64);
  }

  void send_welcome(const uint8_t *hello_body) {
    const uint8_t *Cp = hello_body + 80; // C', from HELLO
    uint8_t k[32];
    // beforenm(C', s) is the same shared secret the client computes as
    // beforenm(S, c') -- the server side of the same agreement.
    Mads::box_beforenm(k, Cp, BROKER_SECRET);
    uint8_t nonce[24];
    std::memcpy(nonce, "WELCOME-", 8);
    std::memcpy(nonce + 8, WELCOME_LONG_NONCE, 16);

    uint8_t body[168];
    body[0] = 7;
    std::memcpy(body + 1, "WELCOME", 7);
    std::memcpy(body + 8, WELCOME_LONG_NONCE, 16);
    uint8_t pt[128];
    std::memcpy(pt, _Sp, 32);
    std::memcpy(pt + 32, _cookie, 96);
    Mads::secretbox_seal(body + 24, pt, 128, nonce, k);
    push_frame(body, sizeof(body));
  }

  void send_ready() {
    Mads::box_beforenm(_precom, _Cp, BROKER_TRANSIENT_SECRET);
    uint8_t md[32];
    const size_t mdlen = Mads::zmtp_build_metadata(md, sizeof(md), "PUB");
    uint8_t body[6 + 8 + 16 + 32];
    body[0] = 5;
    std::memcpy(body + 1, "READY", 5);
    mb_put_u64_be(body + 6, 1); // broker's own outgoing nonce
    uint8_t nonce[24];
    std::memcpy(nonce, "CurveZMQREADY---", 16);
    mb_put_u64_be(nonce + 16, 1);
    Mads::secretbox_seal(body + 14, md, mdlen, nonce, _precom);
    push_frame(body, 6 + 8 + 16 + mdlen);
    _done = true;
  }

  void advance() {
    for (;;) {
      if (!_greeted) {
        if (_in.size() < 64)
          return;
        _in.erase(_in.begin(), _in.begin() + 64);
        _greeted = true;
        push_greeting();
        continue;
      }
      if (_in.size() < 2)
        return;
      const uint8_t flags = _in[0];
      size_t hdr, blen;
      if (flags & Mads::ZmtpSession::FLAG_LARGE) {
        if (_in.size() < 9)
          return;
        blen = static_cast<size_t>(mb_get_u64_be(&_in[1]));
        hdr = 9;
      } else {
        blen = _in[1];
        hdr = 2;
      }
      if (_in.size() < hdr + blen)
        return;
      const uint8_t *body = _in.data() + hdr;
      if (blen >= 6 && body[0] == 5 && std::memcmp(body + 1, "HELLO", 5) == 0) {
        hello.assign(body, body + blen);
        std::memcpy(_Cp, body + 80, 32);
        send_welcome(body);
      } else if (blen >= 9 && body[0] == 8 &&
                 std::memcmp(body + 1, "INITIATE", 8) == 0) {
        initiate.assign(body, body + blen);
        send_ready();
      }
      _in.erase(_in.begin(), _in.begin() + hdr + blen);
      if (_done)
        return;
    }
  }
};

/// Arms a session by running a real handshake against `mock`.
inline bool mock_arm(MockBroker &mock, Mads::ZmtpSession &s,
                     Mads::CurveKeys &keys, const char *socket_type = "PUB") {
  std::memset(&keys, 0, sizeof(keys));
  std::memcpy(keys.client_secret, CLIENT_SECRET, 32);
  crypto_x25519_public_key(keys.client_public, CLIENT_SECRET);
  std::memcpy(keys.server_public, mock.server_public(), 32);
  s.set_curve_keys(&keys);
  s.reset();
  return s.handshake(socket_type, 1000);
}
