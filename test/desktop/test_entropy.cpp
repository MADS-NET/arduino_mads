// Phase 3 entropy backend test. Dual-purpose, selected by
// MADS_CURVE_TEST_ENTROPY (see the Makefile: it builds this twice, once
// per mode):
//
//   without the define: exercises the real desktop backend
//     (entropy_desktop.cpp's /dev/urandom path) -- a smoke test, not a
//     statistical one: entropy_init() must succeed, entropy_fill() must
//     succeed and must not return an all-zero or repeated buffer.
//
//   with the define: exercises the injectable deterministic stream, by
//     printing its output as hex to stdout. The Makefile's `test` target
//     runs the resulting binary twice, as two independent OS processes,
//     and diffs the output -- proving "identical bytes across runs"
//     (CURVE_PLAN.md Sec 3.2's acceptance) the only way that claim can
//     actually be demonstrated: not by calling entropy_fill() twice in
//     one process (which just shows the generator advances, not that a
//     fresh run reproduces it), but by two separate process invocations.
#include "entropy.hpp"

#include <cstdio>
#include <cstring>

using namespace Mads;

int main() {
#ifdef MADS_CURVE_TEST_ENTROPY
  uint8_t buf[64];
  if (!entropy_init() || !entropy_fill(buf, sizeof buf)) {
    std::fprintf(stderr, "test_entropy: FAILED -- entropy_fill() returned "
                         "false under the test hook (should never happen)\n");
    return 1;
  }
  for (unsigned char byte : buf)
    std::printf("%02x", byte);
  std::printf("\n");
  return 0;
#else
  if (!entropy_init()) {
    std::fprintf(stderr,
                 "test_entropy: FAILED -- entropy_init() returned false "
                 "(no /dev/urandom in this environment?)\n");
    return 1;
  }

  uint8_t a[32], b[32];
  if (!entropy_fill(a, sizeof a) || !entropy_fill(b, sizeof b)) {
    std::fprintf(stderr,
                 "test_entropy: FAILED -- entropy_fill() returned false\n");
    return 1;
  }

  bool a_all_zero = true;
  for (uint8_t byte : a)
    if (byte != 0)
      a_all_zero = false;
  if (a_all_zero) {
    std::fprintf(stderr, "test_entropy: FAILED -- fill was all-zero\n");
    return 1;
  }

  if (memcmp(a, b, sizeof a) == 0) {
    std::fprintf(stderr, "test_entropy: FAILED -- two independent fills "
                         "were identical\n");
    return 1;
  }

  std::printf("test_entropy: desktop backend smoke test PASSED\n");
  return 0;
#endif
}
