// MADS CURVE -- Phase 8 hardware diagnostic (CURVE_PLAN.md Phase 8).
//
// Runs the three Phase 8 checks that need neither a broker nor WiFi:
//
//   1. TRNG gate  -- entropy_init(), then dump 4 KB over Serial. Phase 8's
//                    pass condition is: not constant, no repeated 16-byte
//                    block, and *different across power cycles*. Only the
//                    first two can be judged from a single run; the third
//                    needs two dumps compared offline, which is why the
//                    whole 4 KB is emitted rather than a verdict.
//   2. Stack      -- paint the free gap between the heap break and the live
//                    stack, run the crypto, then find the deepest byte the
//                    stack actually reached. This is the measurement
//                    CURVE_HANDOFF.md Sec 5 asks for, against which the
//                    864-byte static estimate for box_beforenm can be
//                    checked.
//   3. Timing     -- one X25519 (box_beforenm), averaged over 16 runs.
//
// Phase 8 steps 4 and 5 need a completed CURVE handshake (Phases 4-5) and a
// `mads broker --crypto`, so they are deliberately not here.
//
// Build (MADS_ENABLE_CURVE must reach the C compiler too -- Monocypher is C,
// and without it monocypher_unit.c compiles to nothing and the link fails):
//
//   arduino-cli compile --fqbn arduino:renesas_uno:unor4wifi \
//     --library . \
//     --build-property "compiler.cpp.extra_flags=-DMADS_ENABLE_CURVE" \
//     --build-property "compiler.c.extra_flags=-DMADS_ENABLE_CURVE" \
//     test/hardware/phase8_diag

// MadsUnoAgent.h first and deliberately: arduino-cli resolves libraries by
// matching a sketch's #include against library header names, so without the
// library's own entry-point header it never puts src/ on the include path
// and the two below fail to resolve -- `--library` alone does not do it.
#include <MadsUnoAgent.h>

#include <mads/crypto/nacl_box.h>
#include <mads/entropy.hpp>
#include <string.h>

// Provided by the linker script (variants/UNOWIFIR4/fsp.ld).
extern "C" {
extern char __StackTop;
extern char __StackLimit;
extern void *_sbrk(int incr);
}

static const uint32_t PAINT = 0xA5A5A5A5u;
static const size_t DUMP_BYTES = 4096;
static uint8_t g_dump[DUMP_BYTES];

// Lowest address the paint may touch: just above the current heap break, so
// nothing already allocated is clobbered. 4-byte aligned.
static char *paint_floor() {
  uintptr_t base = reinterpret_cast<uintptr_t>(_sbrk(0)) + 256;
  return reinterpret_cast<char *>((base + 3u) & ~uintptr_t(3));
}

static void paint_stack() {
  char here;
  char *lo = paint_floor();
  // Stop well below the live frame: the stack grows down, so &here is
  // roughly the current stack pointer and anything at or above it is live.
  char *hi = &here - 256;
  for (char *p = lo; p + 4 <= hi; p += 4)
    *reinterpret_cast<uint32_t *>(p) = PAINT;
}

// Deepest stack penetration since paint_stack(), as bytes below __StackTop.
static size_t stack_high_water() {
  char *p = paint_floor();
  char *top = &__StackTop;
  while (p + 4 <= top && *reinterpret_cast<uint32_t *>(p) == PAINT)
    p += 4;
  return static_cast<size_t>(top - p);
}

static void print_hex_byte(uint8_t b) {
  static const char hex[] = "0123456789abcdef";
  Serial.write(hex[b >> 4]);
  Serial.write(hex[b & 0x0F]);
}

// The two single-run checks from Phase 8 step 1.
static void analyse_dump() {
  bool all_zero = true, all_ff = true;
  for (size_t i = 0; i < DUMP_BYTES; ++i) {
    if (g_dump[i] != 0x00) all_zero = false;
    if (g_dump[i] != 0xFF) all_ff = false;
  }
  Serial.print("constant-all-zero: ");
  Serial.println(all_zero ? "YES (FAIL)" : "no");
  Serial.print("constant-all-ff:   ");
  Serial.println(all_ff ? "YES (FAIL)" : "no");

  size_t blocks = DUMP_BYTES / 16;
  size_t repeats = 0;
  for (size_t i = 1; i < blocks; ++i)
    for (size_t j = 0; j < i; ++j)
      if (memcmp(&g_dump[i * 16], &g_dump[j * 16], 16) == 0) {
        ++repeats;
        break;
      }
  Serial.print("repeated 16-byte blocks: ");
  Serial.print(repeats);
  Serial.println(repeats ? "  (FAIL)" : "  (ok)");

  // Not a Phase 8 criterion, but a dead giveaway if the TRNG is degenerate:
  // a byte histogram that is wildly off uniform. 4096 bytes over 256 values
  // is a mean of 16 per value.
  uint16_t hist[256] = {0};
  for (size_t i = 0; i < DUMP_BYTES; ++i)
    ++hist[g_dump[i]];
  uint16_t lo = 0xFFFF, hi = 0;
  size_t zero_count = 0;
  for (int i = 0; i < 256; ++i) {
    if (hist[i] < lo) lo = hist[i];
    if (hist[i] > hi) hi = hist[i];
    if (hist[i] == 0) ++zero_count;
  }
  Serial.print("byte histogram (mean 16): min=");
  Serial.print(lo);
  Serial.print(" max=");
  Serial.print(hi);
  Serial.print(" unseen=");
  Serial.println(zero_count);
}

// The diagnostic is driven by a command byte rather than run straight from
// setup(). Reading it from setup() is a race: the sketch starts as soon as
// the board resets, and whatever is not printed before the host opens the
// port is simply lost. Waiting for a byte makes the capture deterministic.
// entropy_init()'s result is cached, so the "different across power cycles"
// check in Phase 8 step 1 still requires a real reset between runs, not
// just a second command.
static void run_diagnostic() {
  Serial.println();
  Serial.println("=== MADS CURVE Phase 8 diagnostic ===");
  Serial.print("boot millis at run: ");
  Serial.println(millis());
  Serial.print("free gap (heap break -> __StackTop): ");
  Serial.println(static_cast<uint32_t>(&__StackTop - paint_floor()));
  Serial.print("reserved stack (__StackTop - __StackLimit): ");
  Serial.println(static_cast<uint32_t>(&__StackTop - &__StackLimit));

  // ---- 1. TRNG gate -------------------------------------------------
  bool ok = Mads::entropy_init();
  Serial.print("entropy_init: ");
  Serial.println(ok ? "OK" : "FAILED");
  if (!ok) {
    Serial.println("=== ABORT: TRNG unusable, everything downstream is insecure ===");
    return;
  }

  if (!Mads::entropy_fill(g_dump, DUMP_BYTES)) {
    Serial.println("entropy_fill(4096): FAILED");
    Serial.println("=== ABORT ===");
    return;
  }
  analyse_dump();

  Serial.println("---- BEGIN 4096-byte dump ----");
  for (size_t i = 0; i < DUMP_BYTES; i += 32) {
    for (size_t j = 0; j < 32; ++j)
      print_hex_byte(g_dump[i + j]);
    Serial.println();
  }
  Serial.println("---- END dump ----");

  // ---- 2 + 3. Stack and timing around the real crypto ----------------
  // Painted immediately before the work and read immediately after, with no
  // Serial calls in between, so the watermark reflects the crypto and not
  // the printing.
  uint8_t pk[32], sk[32], precom[32];
  if (!Mads::entropy_fill(sk, 32) || !Mads::entropy_fill(pk, 32)) {
    Serial.println("entropy_fill(keys): FAILED");
    return;
  }
  // A random 32-byte string is not a valid X25519 public key in general,
  // but scalarmult runs the same code path either way -- this measures
  // cost and stack, not agreement.
  paint_stack();
  uint32_t t_start = micros();
  const int N = 16;
  bool bok = true;
  for (int i = 0; i < N; ++i)
    bok &= Mads::box_beforenm(precom, pk, sk);
  uint32_t t_end = micros();
  size_t water = stack_high_water();

  Serial.print("box_beforenm ok: ");
  Serial.println(bok ? "yes" : "no");
  Serial.print("box_beforenm (one X25519 + HSalsa20) avg us: ");
  Serial.println((t_end - t_start) / N);
  Serial.print("stack high-water below __StackTop (bytes): ");
  Serial.println(static_cast<uint32_t>(water));
  Serial.print("  ... of which beyond the 1024-byte reservation: ");
  long beyond = static_cast<long>(water) -
                static_cast<long>(&__StackTop - &__StackLimit);
  Serial.println(beyond > 0 ? beyond : 0);

  Serial.println("=== END ===");
}

void setup() {
  Serial.begin(115200);
}

void loop() {
  if (Serial.available() && Serial.read() == 'g')
    run_diagnostic();
}
