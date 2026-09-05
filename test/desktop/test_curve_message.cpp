// CURVE MESSAGE framing tests (CURVE_PLAN.md Phase 5).
//
// The peer here is MockBroker, which encrypts and decrypts with the
// *opposite* directional nonce prefix to the client. That matters: a client
// round-tripped only against itself would pass even if both directions
// shared a prefix, which would be a silent interoperability bug against a
// real broker and a genuine cryptographic one.
#include "mock_broker.h"

#include "curve.hpp"
#include "zmtp_session.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

static int g_checks = 0;
static int g_failures = 0;
static void check(bool ok, const char *what) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::fprintf(stderr, "  FAIL: %s\n", what);
  }
}

/// Wraps MockBroker and records how deep the stack got inside write(),
/// which is called from the middle of the two-pass encrypt loop. Comparing
/// that depth across blob sizes is a direct test of Phase 5's acceptance
/// criterion: blob publish RAM must not scale with blob size.
class DepthProbe : public Mads::Transport {
public:
  explicit DepthProbe(MockBroker &m) : _m(m) {}
  const char *deepest = nullptr;

  bool connect(const char *h, uint16_t p) override { return _m.connect(h, p); }
  bool connected() override { return _m.connected(); }
  void close() override { _m.close(); }
  bool available() override { return _m.available(); }
  int read(uint8_t *b, size_t n, uint32_t t) override {
    return _m.read(b, n, t);
  }
  bool write(const uint8_t *d, size_t n) override {
    char here;
    if (!deepest || &here < deepest)
      deepest = &here;
    return _m.write(d, n);
  }

private:
  MockBroker &_m;
};

int main() {
  // --- 1. Send: payload and flags survive, in the broker's own decoder ----
  {
    MockBroker mock;
    Mads::CurveKeys keys;
    Mads::ZmtpSession s(mock);
    check(mock_arm(mock, s, keys), "handshake arms the session");

    const char *topic = "test_topic";
    uint8_t big[700];
    for (size_t i = 0; i < sizeof(big); ++i)
      big[i] = static_cast<uint8_t>(i * 7 + 3);

    check(s.send_frame(topic, true), "send small frame (MORE)");
    check(s.send_frame(big, sizeof(big), false), "send 700-byte frame");

    size_t off = 0;
    uint8_t flags;
    std::vector<uint8_t> payload;
    uint64_t nonce;
    bool large;

    check(mock.decode_message(off, flags, payload, nonce, large),
          "broker decodes frame 1");
    check(flags == Mads::ZmtpSession::FLAG_MORE, "frame 1 MORE bit is set");
    check(payload.size() == std::strlen(topic) &&
              std::memcmp(payload.data(), topic, payload.size()) == 0,
          "frame 1 payload round-trips");
    check(nonce == 3, "frame 1 uses nonce 3 (handshake left the counter at 3)");
    check(!large, "frame 1 is a small frame");

    check(mock.decode_message(off, flags, payload, nonce, large),
          "broker decodes frame 2");
    check(flags == 0, "frame 2 has no MORE bit");
    check(payload.size() == sizeof(big) &&
              std::memcmp(payload.data(), big, sizeof(big)) == 0,
          "frame 2 payload round-trips (two-pass path)");
    check(nonce == 4, "frame 2 uses nonce 4");
    check(large, "frame 2 sets FLAG_LARGE");
    check(off == mock.rx_raw.size(), "no trailing bytes");
  }

  // --- 2. The FLAG_LARGE threshold is on the *expanded* length ------------
  // Appendix C pitfall 5: overhead is a flat 33, so 222 bytes of payload is
  // the last small frame (255) and 223 is the first large one (256).
  {
    for (size_t len : {size_t(222), size_t(223)}) {
      MockBroker mock;
      Mads::CurveKeys keys;
      Mads::ZmtpSession s(mock);
      mock_arm(mock, s, keys);
      std::vector<uint8_t> buf(len, 0xAB);
      s.send_frame(buf.data(), len, false);
      size_t off = 0;
      uint8_t flags;
      std::vector<uint8_t> payload;
      uint64_t nonce;
      bool large = false;
      check(mock.decode_message(off, flags, payload, nonce, large),
            "threshold frame decodes");
      check(large == (len + 33 > 255),
            len == 222 ? "222-byte payload stays small (255)"
                       : "223-byte payload goes large (256)");
    }
  }

  // --- 3. Receive, including the streaming trio ---------------------------
  {
    MockBroker mock;
    Mads::CurveKeys keys;
    Mads::ZmtpSession s(mock);
    mock_arm(mock, s, keys);

    uint8_t body[400];
    for (size_t i = 0; i < sizeof(body); ++i)
      body[i] = static_cast<uint8_t>(255 - i % 251);
    mock.queue(mock.encode_message(Mads::ZmtpSession::FLAG_MORE, body,
                                   sizeof(body), mock.next_out_nonce()));

    uint8_t flags;
    uint64_t len;
    check(s.recv_frame_header(flags, len, 100), "recv header");
    check(flags == Mads::ZmtpSession::FLAG_MORE, "MORE bit decrypted");
    check(len == sizeof(body), "len is the plaintext length, not the wire one");
    uint8_t got[400];
    check(s.recv_frame_body(got, sizeof(got), len, 100), "recv body");
    check(std::memcmp(got, body, sizeof(body)) == 0, "payload round-trips");

    // Streaming trio over a second frame.
    mock.queue(mock.encode_message(0, body, sizeof(body),
                                   mock.next_out_nonce()));
    check(s.recv_frame_header(flags, len, 100), "recv header (streaming)");
    check(s.begin_recv_body(len), "begin_recv_body");
    std::vector<uint8_t> acc;
    uint64_t left = len;
    while (left) {
      uint8_t chunk[64];
      size_t want = left < sizeof(chunk) ? static_cast<size_t>(left)
                                         : sizeof(chunk);
      int n = s.read_body_chunk(chunk, want, 100);
      check(n > 0, "read_body_chunk returns data");
      if (n <= 0)
        break;
      acc.insert(acc.end(), chunk, chunk + n);
      left -= static_cast<uint64_t>(n);
    }
    check(s.end_recv_body(), "end_recv_body authenticates");
    check(acc.size() == sizeof(body) &&
              std::memcmp(acc.data(), body, sizeof(body)) == 0,
          "streamed payload round-trips");
  }

  // --- 4. Tamper: tag, ciphertext, nonce ----------------------------------
  // Each flips exactly one bit in an otherwise valid frame.
  {
    struct { const char *name; size_t offset; } spots[] = {
        {"tag", 2 + 16},          // first byte of the Poly1305 tag
        {"ciphertext", 2 + 33},   // first payload byte
        {"nonce", 2 + 8},         // first byte of the short nonce
    };
    for (auto &spot : spots) {
      MockBroker mock;
      Mads::CurveKeys keys;
      Mads::ZmtpSession s(mock);
      mock_arm(mock, s, keys);
      uint8_t body[64];
      std::memset(body, 0x5A, sizeof(body));
      auto frame = mock.encode_message(0, body, sizeof(body),
                                       mock.next_out_nonce());
      frame[spot.offset] ^= 0x01;
      mock.queue(frame);

      uint8_t flags;
      uint64_t len;
      uint8_t got[64];
      const bool hdr_ok = s.recv_frame_header(flags, len, 100);
      // A flipped nonce is caught at the header (it also breaks the MAC);
      // tag and ciphertext flips are caught by finish().
      const bool ok = hdr_ok && s.recv_frame_body(got, sizeof(got), len, 100);
      check(!ok, spot.name);
    }
  }

  // --- 5. skip_frame_body still authenticates -----------------------------
  // The easiest of the five pitfalls to get wrong, because a wrong answer
  // has no symptom (Appendix C pitfall 4).
  {
    MockBroker mock;
    Mads::CurveKeys keys;
    Mads::ZmtpSession s(mock);
    mock_arm(mock, s, keys);
    uint8_t body[64];
    std::memset(body, 0x33, sizeof(body));
    auto frame = mock.encode_message(0, body, sizeof(body),
                                     mock.next_out_nonce());
    frame[2 + 33] ^= 0x80; // corrupt the ciphertext
    mock.queue(frame);
    uint8_t flags;
    uint64_t len;
    check(s.recv_frame_header(flags, len, 100), "header of a doomed frame");
    check(!s.skip_frame_body(len, 100),
          "skip_frame_body rejects a bad MAC rather than ignoring it");
  }

  // --- 6. Replay ----------------------------------------------------------
  {
    MockBroker mock;
    Mads::CurveKeys keys;
    Mads::ZmtpSession s(mock);
    mock_arm(mock, s, keys);
    uint8_t body[32];
    std::memset(body, 0x11, sizeof(body));
    auto frame = mock.encode_message(0, body, sizeof(body),
                                     mock.next_out_nonce());
    mock.queue(frame);
    uint8_t flags;
    uint64_t len;
    uint8_t got[32];
    check(s.recv_frame_header(flags, len, 100) &&
              s.recv_frame_body(got, sizeof(got), len, 100),
          "first delivery accepted");
    mock.queue(frame); // byte-identical replay
    check(!s.recv_frame_header(flags, len, 100),
          "replayed frame rejected on the nonce check");
  }

  // --- 7. Blob RAM does not scale with blob size --------------------------
  // Phase 5's acceptance criterion. Measures how deep the stack actually
  // gets inside the encrypt loop for a 1 KB and a 16 KB blob; the two-pass
  // path streams in 64-byte chunks, so the depths must match exactly.
  {
    long depth[2] = {0, 0};
    size_t sizes[2] = {1024, 16384};
    for (int i = 0; i < 2; ++i) {
      MockBroker mock;
      DepthProbe probe(mock);
      Mads::CurveKeys keys;
      Mads::ZmtpSession s(probe);
      // Arm through the probe so the handshake's own writes are included.
      check(mock_arm(mock, s, keys), "arm through the depth probe");
      const char *base = probe.deepest;
      probe.deepest = nullptr;
      std::vector<uint8_t> blob(sizes[i], 0xC7);
      check(s.send_frame(blob.data(), blob.size(), false), "blob publish");
      depth[i] = base - probe.deepest; // bytes deeper than the handshake
      (void)base;
    }
    std::printf("  stack depth in write(): 1 KB blob %ld B, 16 KB blob %ld B\n",
                depth[0], depth[1]);
    check(depth[0] == depth[1],
          "stack depth identical for 1 KB and 16 KB blobs");
  }

  std::printf("test_curve_message: %d checks, %d failures\n", g_checks,
              g_failures);
  return g_failures ? 1 : 0;
}
