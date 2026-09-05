// Golden vectors for the CURVE handshake (DEVELOPER.md).
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
// unverified run just freezes a bug (DEVELOPER.md).
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
#include "mock_broker.h"

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

#include "curve_golden.inc"

static int g_checks = 0;
static int g_failures = 0;
static void check(bool ok, const char *what) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::fprintf(stderr, "  FAIL: %s\n", what);
  }
}

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
    // Each vector starts from the same seed, so re-recording one does not
    // cascade into the others.
    Mads::entropy_test_reset();

    Mads::ZmtpSession s(mock);
    const bool ok = mock_arm(mock, s, keys, c.type);
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
