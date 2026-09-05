// CURVE_PLAN.md Phase 8 step 2: the stack high-water mark with the *real
// agent* running, not the crypto alone.
//
// The earlier 1612-1668 B figure came from a sketch that barely touched the
// heap. That matters, because on this board the heap and the stack grow
// toward each other in one shared region and nothing faults when they meet
// -- and ArduinoJson v7 allocates for every JsonDocument. So the number
// worth having is not "how deep does the stack go" but "how much room is
// left between the two".
//
// Also times Agent::connected(), which is a round-trip to the ESP32 and is
// suspected of being most of the fixed per-publish cost.
//
// Build:
//   arduino-cli compile --upload -p <port> --fqbn arduino:renesas_uno:unor4wifi \
//     --library . --build-property "build.extra_flags=-DMADS_ENABLE_CURVE" \
//     test/hardware/stack_probe
#include <MadsUnoAgent.h>
#include "arduino_secrets.h"

#ifndef SECRET_SETTINGS_PORT
#define SECRET_SETTINGS_PORT 9092
#endif

extern "C" {
extern char __StackTop;
extern char __StackLimit;
extern void *_sbrk(int incr);
}

static const uint32_t PAINT = 0xA5A5A5A5u;
Mads::Agent agent;
JsonDocument doc;
static bool g_ready = false;
static bool g_painted = false;

static char *heap_break() { return reinterpret_cast<char *>(_sbrk(0)); }

static char *align4(char *p) {
  return reinterpret_cast<char *>((reinterpret_cast<uintptr_t>(p) + 3u) & ~uintptr_t(3));
}

// Paint the free gap. Interrupts must be masked: on Cortex-M an ISR pushes
// onto this same stack, below the current SP, i.e. straight into the region
// being swept -- and an ISR whose frame is overwritten returns to a
// corrupted address.
static void paint() {
  char here;
  char *lo = align4(heap_break() + 256);
  char *hi = &here - 1024;
  noInterrupts();
  for (char *p = lo; p + 4 <= hi; p += 4)
    *reinterpret_cast<uint32_t *>(p) = PAINT;
  interrupts();
}

/// Lowest address the stack reached, as bytes below __StackTop. Scans from
/// above the *current* heap break, so heap growth since painting is not
/// mistaken for stack depth -- the two are indistinguishable by content.
static size_t high_water() {
  char *p = align4(heap_break() + 256);
  char *top = &__StackTop;
  while (p + 4 <= top && *reinterpret_cast<uint32_t *>(p) == PAINT)
    p += 4;
  return static_cast<size_t>(top - p);
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 3000) {}
#ifdef MADS_ENABLE_CURVE
  agent.set_crypto(SECRET_CURVE_CLIENT_PUBLIC, SECRET_CURVE_CLIENT_SECRET,
                   SECRET_CURVE_BROKER_PUBLIC);
#endif
}

void loop() {
  if (!g_ready) {
    Serial.println("connecting...");
    if (!agent.begin(SECRET_WIFI_SSID, SECRET_WIFI_PASS, SECRET_BROKER_HOST,
                     SECRET_SETTINGS_PORT, "uno_r4", "stackprobe")) {
      Serial.println("  begin() failed");
      delay(10000);
      return;
    }
    g_ready = true;
    Serial.print("connected, encrypted=");
    Serial.println(agent.crypto_enabled() ? "yes" : "no");
    return;
  }

  // Paint only once the agent is fully up and the heap has settled, so the
  // measurement covers steady-state operation rather than one-off setup.
  if (!g_painted) {
    paint();
    g_painted = true;
    Serial.println("painted; measuring steady-state publishing");
    return;
  }

  static int n = 0;
  doc.clear();
  doc["a0"] = analogRead(A0);
  doc["n"] = n;
  agent.publish(doc);

  // How much unread data is sitting on the PUB link, and what connected()
  // costs before and after clearing it. connected() short-circuits to 1
  // whenever available() > 0, so a non-empty buffer means it never asks the
  // ESP32 anything -- which is why a dead link goes unnoticed.
  uint32_t t0 = micros();
  const bool up = agent.connected();
  const uint32_t connected_us = micros() - t0;

  const size_t drained = agent.drain_pub();

  t0 = micros();
  const bool up2 = agent.connected();
  const uint32_t connected_after_us = micros() - t0;
  (void)up2;

  if (++n % 100 == 0) {
    const char *hb = heap_break();
    const size_t water = high_water();
    char *deepest = &__StackTop - water;
    Serial.println();
    Serial.print("after ");
    Serial.print(n);
    Serial.println(" publishes:");
    Serial.print("  heap break        0x");
    Serial.println((uint32_t)hb, HEX);
    Serial.print("  deepest stack     0x");
    Serial.print((uint32_t)deepest, HEX);
    Serial.print("   (");
    Serial.print((uint32_t)water);
    Serial.println(" B below __StackTop)");
    Serial.print("  free gap left     ");
    Serial.print((uint32_t)(deepest - hb));
    Serial.println(" B between heap and deepest stack");
    Serial.print("  reserved stack    ");
    Serial.print((uint32_t)(&__StackTop - &__StackLimit));
    Serial.println(" B");
    Serial.print("  connected() cost  ");
    Serial.print(connected_us);
    Serial.print(" us  (link=");
    Serial.print(up ? "up" : "down");
    Serial.println(")");
    Serial.print("  drained from PUB  ");
    Serial.print((uint32_t)drained);
    Serial.println(" B");
    Serial.print("  connected() after ");
    Serial.print(connected_after_us);
    Serial.println(" us  <- if this jumps, it is now really asking the ESP32");
  }
  delay(50);
}
