// MADS agent over CURVE: the same publish loop as minimal_pub, encrypted.
//
// BUILDING. A #define in the .ino cannot reach the library's translation
// units, so MADS_ENABLE_CURVE has to come from the build:
//
//   arduino-cli compile --fqbn arduino:renesas_uno:unor4wifi \
//     --build-property "build.extra_flags=-DMADS_ENABLE_CURVE" \
//     examples/crypto_pub
//
// build.extra_flags is the one to use because renesas_uno's platform.txt
// substitutes it into *both* the C and the C++ recipe. That matters:
// Monocypher is C, so a C++-only flag
// ("compiler.cpp.extra_flags=-DMADS_ENABLE_CURVE") compiles cleanly and then
// fails at link with undefined references to crypto_x25519 and crypto_wipe.
// If you need the two-flag form, set compiler.c.extra_flags as well.
//
// Note --build-property *replaces* a property rather than appending to it,
// so fold in any other flags you were already passing to it.
//
// There is deliberately no build_opt.h here. It cannot work on this core:
// arduino:renesas_uno 1.6.0's platform.txt never references
// {build.opt.path} in any recipe, so the file is read by nobody. Verified
// empirically on arduino-cli 1.0.2 and 1.2.2 -- the sketch simply builds
// without CURVE. The #else branch in setup() below exists to catch exactly
// that: a build that quietly lost its encryption should refuse to run, not
// connect in clear.
//
// BROKER SIDE. Run it with --crypto, put this board's .pub in its keys
// directory, and restart it. Setting [broker] auth_verbose = true in
// mads.ini makes it log `granted` or `DENIED` per attempt, which is the
// only useful diagnostic when a board is refused.
#include <MadsUnoAgent.h>
#include "arduino_secrets.h" // copy from arduino_secrets.h.example, gitignored

const char *WIFI_SSID = SECRET_WIFI_SSID;
const char *WIFI_PASS = SECRET_WIFI_PASS;
const char *BROKER_HOST = SECRET_BROKER_HOST;
// mads.ini [broker] settings_address port. Override it in arduino_secrets.h
// (#define SECRET_SETTINGS_PORT 9192) when the broker is not on the default.
#ifndef SECRET_SETTINGS_PORT
#define SECRET_SETTINGS_PORT 9092
#endif
const uint16_t SETTINGS_PORT = SECRET_SETTINGS_PORT;

Mads::Agent agent;
JsonDocument doc;

#ifdef MADS_ENABLE_CURVE
// Prints why a handshake failed. This is the only diagnostic available on
// the board, and each value points at a different fix.
static const char *curve_error_text(Mads::CurveError e) {
  switch (e) {
  case Mads::CurveError::none:       return "none";
  case Mads::CurveError::no_entropy: return "TRNG unavailable -- refusing to use weak keys";
  case Mads::CurveError::greeting:   return "broker is not running --crypto";
  case Mads::CurveError::welcome:    return "malformed WELCOME";
  case Mads::CurveError::mac:        return "bad MAC -- wrong broker public key?";
  case Mads::CurveError::rejected:   return "broker refused this key: copy the .pub into its keys dir and RESTART it";
  case Mads::CurveError::timeout:    return "timed out";
  case Mads::CurveError::disconnected: return "broker hung up -- client public and secret may not be a pair";
  case Mads::CurveError::protocol:   return "protocol error";
  }
  return "?";
}
#endif

// ---------------------------------------------------------------------------
// Status LED. One lamp, five states, read at a glance from across a room.
//
// The encoding is 8 slots of 250 ms, so one full cycle is 2 s:
//
//   no WiFi          #.......   one brief blink, mostly dark
//   WiFi, no broker  ########   solid
//   broker, plain    ####....   one long pulse per cycle
//   broker, CURVE    ##.##...   TWO pulses per cycle
//   CURVE rejected   #.#.#.#.   fast flutter -- needs a human
//
// Two deliberate choices:
//
// "Not connected" blinks rather than staying dark. Dark then means exactly
// one thing -- no power, or firmware that is not running -- which is the
// most useful single bit a status lamp can carry. (This board can wedge with
// USB still enumerated and the firmware dead; a lamp that was merely off
// would say nothing about that.)
//
// Plain and encrypted differ by pulse COUNT, not duty cycle. Counting one
// flash versus two is instant; judging a 50% duty against a 67% one is not,
// and mistaking unencrypted for encrypted is precisely the error that must
// not be easy to make.
static const uint8_t LED_SLOT_MS = 250;
// Plain constants rather than an enum, and led_state() returns uint8_t:
// the Arduino builder hoists auto-generated prototypes above everything in
// the .ino, so a function returning a type declared here fails to compile.
static const uint8_t LED_NO_WIFI = 0;
static const uint8_t LED_WIFI_ONLY = 1;
static const uint8_t LED_BROKER_PLAIN = 2;
static const uint8_t LED_BROKER_CURVE = 3;
static const uint8_t LED_CURVE_REJECTED = 4;
static const uint8_t LED_PATTERN[] = {
  0b10000000, // no WiFi
  0b11111111, // WiFi, no broker
  0b11110000, // broker, unencrypted
  0b11011000, // broker, encrypted
  0b10101010, // CURVE rejected, backing off
};

static uint8_t led_state() {
  if (WiFi.status() != WL_CONNECTED)
    return LED_NO_WIFI;
#ifdef MADS_ENABLE_CURVE
  // Backed off past the base interval means handshakes are being refused --
  // deterministic, and it will not fix itself without someone adding this
  // board's .pub to the broker and restarting it.
  if (agent.crypto_enabled() && agent.curve_backoff() > agent.reconnect_interval())
    return LED_CURVE_REJECTED;
#endif
  if (!agent.connected())
    return LED_WIFI_ONLY;
  // crypto_enabled() is false in a non-CURVE build, so this needs no #ifdef.
  return agent.crypto_enabled() ? LED_BROKER_CURVE : LED_BROKER_PLAIN;
}

static void led_update() {
  const uint8_t slot = (millis() / LED_SLOT_MS) % 8;
  const bool on = (LED_PATTERN[led_state()] >> (7 - slot)) & 1;
  digitalWrite(LED_BUILTIN, on ? HIGH : LOW);
}

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(115200);
  while (!Serial && millis() < 3000) {}

#ifdef MADS_ENABLE_CURVE
  Serial.println("CURVE compiled in");
  if (!agent.set_crypto(SECRET_CURVE_CLIENT_PUBLIC, SECRET_CURVE_CLIENT_SECRET,
                        SECRET_CURVE_BROKER_PUBLIC)) {
    // Nothing is armed on failure, so the agent would silently fall back to
    // an unencrypted connection. Stop instead of doing that quietly.
    Serial.println("set_crypto() FAILED -- a key is not valid Z85.");
    Serial.println("Each must be exactly the 40 characters from the key");
    Serial.println("file, with no quotes, spaces or newline included.");
    while (true)
      delay(1000);
  }
#else
  // Reached when the build did not define MADS_ENABLE_CURVE -- most likely
  // build_opt.h being ignored. Say so rather than connecting in clear.
  Serial.println("CURVE is NOT compiled in: this build would connect");
  Serial.println("unencrypted. See this sketch's header for the explicit");
  Serial.println("--build-property flags.");
  while (true)
    delay(1000);
#endif

  bool ok = agent.begin(WIFI_SSID, WIFI_PASS, BROKER_HOST, SETTINGS_PORT,
                        "uno_r4", "sensors");
  Serial.println(ok ? "MADS agent ready (CURVE)" : "MADS agent begin() failed");
#ifdef MADS_ENABLE_CURVE
  if (!ok) {
    Serial.print("  reason: ");
    Serial.println(curve_error_text(agent.last_curve_error()));
  }
#endif
}

void loop() {
  // The LED is driven every pass. Rendering a 250 ms pattern from a loop
  // that blocked for delay(200) plus a publish would alias badly -- and the
  // pulse count, which is the whole point, is what aliasing destroys. So the
  // publish runs on a millis() schedule instead of a delay().
  led_update();

  static uint32_t last_publish = 0;
  if (millis() - last_publish < 200)
    return;
  last_publish = millis();

  doc.clear();
  doc["a0"] = analogRead(A0);

  bool ok = agent.publish(doc);
  Serial.print(ok ? "published " : "publish FAILED ");
  Serial.println(agent.last_publish_json());

#ifdef MADS_ENABLE_CURVE
  // A rejected handshake backs off exponentially instead of burning four
  // X25519 multiplications every second on a failure that cannot fix
  // itself. Say so, so a board that has gone quiet can explain why.
  if (!ok && agent.curve_backoff() > agent.reconnect_interval()) {
    Serial.print("  CURVE rejected; retrying every ");
    Serial.print(agent.curve_backoff());
    Serial.print(" ms -- ");
    Serial.println(curve_error_text(agent.last_curve_error()));
  }
#endif
}
