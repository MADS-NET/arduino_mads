#include "entropy.hpp"

// Board backend: the RA4M1's Secure Crypto Engine TRNG, already linked
// into every UNO R4 sketch via
// variants/UNOWIFIR4/libs/libfsp.a (member hw_sce_p09.o), which defines
// HW_SCE_McuSpecificInit and HW_SCE_GenerateRandomNumberSub. FSP's r_sce.h
// (the real declarations) is not shipped with arduino:renesas_uno, so they
// are declared by hand below.
//
// Verified on hardware 2026-09-05: see DEVELOPER.md. Guarded off entirely on
// the desktop (ARDUINO_ARCH_RENESAS is only ever defined by the Arduino
// builder's recipe.cpp.o.pattern) so it compiles but is never the desktop
// path -- entropy_desktop.cpp provides Mads::entropy_init/entropy_fill
// there instead.
#if defined(MADS_ENABLE_CURVE) && defined(ARDUINO_ARCH_RENESAS)

#include <cstring>

extern "C" {
void HW_SCE_McuSpecificInit(void);
/* Returns FSP_SUCCESS (0) on success; writes 4 words = 16 bytes to out. */
uint32_t HW_SCE_GenerateRandomNumberSub(uint32_t *out);
}

namespace Mads {

namespace {

bool g_init_attempted = false;
bool g_healthy = false;

bool draw16(uint8_t out16[16]) {
  uint32_t words[4];
  if (HW_SCE_GenerateRandomNumberSub(words) != 0)
    return false;
  memcpy(out16, words, 16);
  return true;
}

} // namespace

bool entropy_init() {
  if (g_init_attempted)
    return g_healthy;
  g_init_attempted = true;

  HW_SCE_McuSpecificInit();

  // Crude sanity check: draw 64 bytes as four
  // 16-byte blocks and reject if the whole draw is constant (all-zero or
  // all-0xFF) or if any block repeats the immediately preceding one. This
  // is a dead-TRNG bring-up gate, not a statistical randomness test. The
  // real verification -- 16 KB dumped over Serial and compared across power
  // cycles -- is extras/hardware/phase8_diag; this function cannot do that
  // from software alone.
  uint8_t blocks[4][16];
  for (auto &b : blocks) {
    if (!draw16(b))
      return false; // g_healthy stays false: HW_SCE call itself failed
  }

  bool all_zero = true, all_ff = true;
  for (auto &b : blocks) {
    for (uint8_t byte : b) {
      if (byte != 0x00)
        all_zero = false;
      if (byte != 0xFF)
        all_ff = false;
    }
  }
  if (all_zero || all_ff)
    return false;

  for (int i = 1; i < 4; ++i) {
    if (memcmp(blocks[i], blocks[i - 1], 16) == 0)
      return false;
  }

  g_healthy = true;
  return true;
}

bool entropy_fill(uint8_t *out, size_t n) {
  if (!g_init_attempted && !entropy_init())
    return false;
  if (!g_healthy)
    return false;

  size_t done = 0;
  while (done < n) {
    uint8_t block[16];
    if (!draw16(block))
      return false; // Fail closed mid-stream -- no fallback to random().
    size_t take = (n - done) < 16 ? (n - done) : 16;
    memcpy(out + done, block, take);
    done += take;
  }
  return true;
}

} // namespace Mads

#endif // MADS_ENABLE_CURVE && ARDUINO_ARCH_RENESAS
