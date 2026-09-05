#include "entropy.hpp"

// Desktop backend: /dev/urandom. Guarded off entirely for a board build
// (ARDUINO is defined by the Arduino builder for every sketch -- see
// platform.txt's recipe.cpp.o.pattern, "-DARDUINO={runtime.ide.version}")
// so this file compiles to nothing at all when targeting the board, and
// entropy_ra4m1.cpp compiles to nothing at all on the desktop -- exactly
// one of the two ever provides Mads::entropy_init/entropy_fill.
#if defined(MADS_ENABLE_CURVE) && !defined(ARDUINO)

// The test hook must be impossible to enable in a board build: if someone
// passes -DMADS_CURVE_TEST_ENTROPY to an actual sketch compile, this must
// fail loudly at compile time, not silently ship a predictable "random"
// stream. This #if can never be true given the file-level guard above (no
// ARDUINO here), but it stays as a second, independent tripwire in case
// this file is ever restructured.
#if defined(MADS_CURVE_TEST_ENTROPY) && defined(ARDUINO)
#error "MADS_CURVE_TEST_ENTROPY must never be defined in a board build"
#endif

#include <cstdio>

namespace Mads {

#ifdef MADS_CURVE_TEST_ENTROPY

// Injectable deterministic stream: a fixed-seed 64-bit LCG (Knuth's MMIX
// constants), NOT cryptographically secure and not meant to be -- its only
// job is making CURVE handshake output byte-reproducible across test runs
// (DEVELOPER.md's golden vectors, out of this pass's scope, but
// the hook itself is Phase 3's). Determinism follows directly from the
// state being process-local and always starting from the same fixed
// value: a fresh process run reproduces the exact same byte sequence for
// the exact same sequence of entropy_fill() calls.
namespace {
uint64_t g_state = 0x2545F4914F6CDD1DULL; // arbitrary fixed non-zero seed
}

bool entropy_init() { return true; }

void entropy_test_reset() { g_state = 0x2545F4914F6CDD1DULL; }

bool entropy_fill(uint8_t *out, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    g_state = g_state * 6364136223846793005ULL + 1442695040888963407ULL;
    out[i] = static_cast<uint8_t>(g_state >> 56);
  }
  return true;
}

#else // !MADS_CURVE_TEST_ENTROPY -- the real backend

namespace {
bool g_init_attempted = false;
bool g_healthy = false;
FILE *g_urandom = nullptr;
} // namespace

bool entropy_init() {
  if (g_init_attempted)
    return g_healthy;
  g_init_attempted = true;
  g_urandom = std::fopen("/dev/urandom", "rb");
  g_healthy = (g_urandom != nullptr);
  return g_healthy;
}

bool entropy_fill(uint8_t *out, size_t n) {
  if (!g_init_attempted && !entropy_init())
    return false;
  if (!g_healthy)
    return false;
  return std::fread(out, 1, n, g_urandom) == n;
}

#endif // MADS_CURVE_TEST_ENTROPY

} // namespace Mads

#endif // MADS_ENABLE_CURVE && !ARDUINO
