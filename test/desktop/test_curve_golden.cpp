// Golden vectors for the CURVE handshake (CURVE_PLAN.md Phase 4.2).
//
// Pins the exact HELLO and INITIATE bytes this client puts on the wire, so
// any later change to the handshake that alters them fails loudly instead of
// silently producing a subtly different protocol.
//
// Why a mock broker rather than a live one: with MADS_CURVE_TEST_ENTROPY the
// *client* is deterministic, but a real broker picks a fresh transient
// keypair and cookie for every connection, so the WELCOME it sends -- and
// therefore the INITIATE computed from it -- is different every run. Pinning
// INITIATE requires a scripted peer. The mock uses fixed test keys and a
// fixed cookie, and it really does the CurveZMQ server side: it opens
// nothing (HELLO's box is not checked here) but it seals a genuine WELCOME
// and READY that the client must be able to open, so the client's crypto is
// still exercised end to end.
//
// The goldens were recorded only after the same code completed a live
// handshake against a real `mads broker --crypto` with auth_verbose showing
// `granted` on all three socket types -- a golden captured from an
// unverified run just freezes a bug (CURVE_HANDOFF.md Sec 7).
//
// IMPORTANT -- what invalidates these vectors. Determinism here is over the
// *sequence* of entropy_fill() calls, not wall time. curve_handshake() draws
// c' (32 bytes) and then the vouch nonce tail (16 bytes), in that order, per
// handshake, with entropy_test_reset() called before each. Reordering or
// resizing those draws changes the goldens, and that is expected, not a
// regression -- re-record and say so in the commit message. A change that
// alters the bytes *without* touching the draw sequence is a real protocol
// change and needs justifying.
//
// Regenerate:  MADS_CURVE_GOLDEN_GENERATE=1 ./build/test_curve_golden
#include "curve.hpp"
#include "entropy.hpp"
#include "transport.hpp"
#include "zmtp_session.hpp"

#include "crypto/monocypher.h"
#include "crypto/nacl_box.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// --- fixed test fixtures ---------------------------------------------------
// Test keys, not secrets: they exist only to make the mock broker's side
// reproducible. Secrets are given; publics are derived, so a typo cannot
// produce a self-consistent but wrong fixture.
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

static int g_checks = 0;
static int g_failures = 0;
static void check(bool ok, const char *what) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::fprintf(stderr, "  FAIL: %s\n", what);
  }
}

static void put_u64_be(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; ++i)
    p[i] = static_cast<uint8_t>((v >> (8 * (7 - i))) & 0xFF);
}

/// A scripted CurveZMQ server over the Transport interface. std::vector is
/// fine here: the no-allocation rule (Sec 1 non-negotiable 9) governs the
/// library, not desktop test scaffolding.
class MockBroker : public Mads::Transport {
public:
  std::vector<uint8_t> hello, initiate;

  MockBroker() {
    crypto_x25519_public_key(_S, BROKER_SECRET);
    crypto_x25519_public_key(_Sp, BROKER_TRANSIENT_SECRET);
    for (int i = 0; i < 96; ++i)
      _cookie[i] = static_cast<uint8_t>(0x40 + i); // opaque to the client
  }
  const uint8_t *server_public() const { return _S; }

  bool connect(const char *, uint16_t) override { return true; }
  bool connected() override { return true; }
  void close() override {}
  bool available() override { return !_out.empty(); }

  bool write(const uint8_t *data, size_t len) override {
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

private:
  std::vector<uint8_t> _in, _out;
  bool _greeted = false;
  uint8_t _S[32], _Sp[32], _cookie[96];

  void push_frame(const uint8_t *body, size_t len) {
    if (len > 255) {
      _out.push_back(Mads::ZmtpSession::FLAG_COMMAND |
                     Mads::ZmtpSession::FLAG_LARGE);
      uint8_t l[8];
      put_u64_be(l, len);
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
    // beforenm(S, c') -- this is the server side of the same agreement.
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

  void send_ready(const uint8_t *initiate_body) {
    // The client's transient public is inside the INITIATE box, which the
    // real broker opens with the cookie key. The mock does not need to: it
    // still has C' from HELLO.
    (void)initiate_body;
    uint8_t precom[32];
    Mads::box_beforenm(precom, _Cp, BROKER_TRANSIENT_SECRET);

    uint8_t md[32];
    const size_t mdlen = Mads::zmtp_build_metadata(md, sizeof(md), "PUB");
    uint8_t body[6 + 8 + 16 + 32];
    body[0] = 5;
    std::memcpy(body + 1, "READY", 5);
    put_u64_be(body + 6, 1); // broker's own outgoing nonce
    uint8_t nonce[24];
    std::memcpy(nonce, "CurveZMQREADY---", 16);
    put_u64_be(nonce + 16, 1);
    Mads::secretbox_seal(body + 14, md, mdlen, nonce, precom);
    push_frame(body, 6 + 8 + 16 + mdlen);
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
        uint64_t l = 0;
        for (int i = 0; i < 8; ++i)
          l = (l << 8) | _in[1 + i];
        blen = static_cast<size_t>(l);
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
        send_ready(body);
      }
      _in.erase(_in.begin(), _in.begin() + hdr + blen);
    }
  }
  uint8_t _Cp[32] = {0};
};

#include "curve_golden.inc"

static void dump(const char *name, const std::vector<uint8_t> &v) {
  std::printf("static const uint8_t %s[%zu] = {\n", name, v.size());
  for (size_t i = 0; i < v.size(); ++i) {
    if (i % 12 == 0)
      std::printf("    ");
    std::printf("0x%02x,", v[i]);
    std::printf((i % 12 == 11 || i + 1 == v.size()) ? "\n" : " ");
  }
  std::printf("};\n");
}

static void compare(const char *what, const std::vector<uint8_t> &got,
                    const uint8_t *want, size_t want_len) {
  if (got.size() != want_len) {
    std::fprintf(stderr, "  %s: length %zu, expected %zu\n", what, got.size(),
                 want_len);
    check(false, what);
    return;
  }
  for (size_t i = 0; i < want_len; ++i) {
    if (got[i] != want[i]) {
      std::fprintf(stderr, "  %s: first difference at byte %zu (got 0x%02x, "
                           "expected 0x%02x)\n",
                   what, i, got[i], want[i]);
      check(false, what);
      return;
    }
  }
  check(true, what);
}

int main() {
  const bool generate = std::getenv("MADS_CURVE_GOLDEN_GENERATE") != nullptr;

  struct { const char *type; const char *hello_name; const char *init_name; }
  cases[] = {
      {"REQ", "GOLDEN_HELLO_REQ", "GOLDEN_INITIATE_REQ"},
      {"PUB", "GOLDEN_HELLO_PUB", "GOLDEN_INITIATE_PUB"},
      {"SUB", "GOLDEN_HELLO_SUB", "GOLDEN_INITIATE_SUB"},
  };

  for (auto &c : cases) {
    MockBroker mock;
    Mads::CurveKeys keys;
    std::memset(&keys, 0, sizeof(keys));
    std::memcpy(keys.client_secret, CLIENT_SECRET, 32);
    crypto_x25519_public_key(keys.client_public, CLIENT_SECRET);
    std::memcpy(keys.server_public, mock.server_public(), 32);

    // Each vector starts from the same seed, so re-recording one does not
    // cascade into the others.
    Mads::entropy_test_reset();

    Mads::ZmtpSession s(mock);
    s.set_curve_keys(&keys);
    s.reset();
    const bool ok = s.handshake(c.type, 1000);
    check(ok, "handshake against the mock broker completes");
    if (!ok) {
      std::fprintf(stderr, "  %s: handshake failed\n", c.type);
      continue;
    }
    check(s.curve_state().nonce_out == 3, "nonce_out == 3");

    if (generate) {
      dump(c.hello_name, mock.hello);
      dump(c.init_name, mock.initiate);
      continue;
    }
    if (std::strcmp(c.type, "REQ") == 0) {
      compare("HELLO/REQ", mock.hello, GOLDEN_HELLO_REQ, sizeof(GOLDEN_HELLO_REQ));
      compare("INITIATE/REQ", mock.initiate, GOLDEN_INITIATE_REQ, sizeof(GOLDEN_INITIATE_REQ));
    } else if (std::strcmp(c.type, "PUB") == 0) {
      compare("HELLO/PUB", mock.hello, GOLDEN_HELLO_PUB, sizeof(GOLDEN_HELLO_PUB));
      compare("INITIATE/PUB", mock.initiate, GOLDEN_INITIATE_PUB, sizeof(GOLDEN_INITIATE_PUB));
    } else {
      compare("HELLO/SUB", mock.hello, GOLDEN_HELLO_SUB, sizeof(GOLDEN_HELLO_SUB));
      compare("INITIATE/SUB", mock.initiate, GOLDEN_INITIATE_SUB, sizeof(GOLDEN_INITIATE_SUB));
    }
  }

  if (generate) {
    std::fprintf(stderr, "test_curve_golden: GENERATED (paste into "
                         "curve_golden.inc)\n");
    return 0;
  }
  std::printf("test_curve_golden: %d checks, %d failures\n", g_checks,
              g_failures);
  return g_failures ? 1 : 0;
}
