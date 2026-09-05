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

void setup() {
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

  delay(200);
}
