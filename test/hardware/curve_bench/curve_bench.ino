// How fast can an UNO R4 WiFi publish over CURVE?
//
// crypto_pub's ~4.8 Hz is a schedule, not a limit: it publishes on a 200 ms
// floor left over from an earlier delay(200). This measures the actual cost
// of a publish so the floor can be set from evidence.
//
// Each stage is timed separately with micros(), because the plausible
// bottlenecks are very different things -- Salsa20/Poly1305 on the RA4M1,
// the SPI hop to the ESP32 and the TCP write, and Serial itself. Printing
// ~85 characters is ~7.4 ms at 115200 on a real UART, which is the entire
// per-iteration budget crypto_pub appeared to have, so it has to be
// measured rather than assumed. (Serial here is native USB CDC, where the
// baud rate is ignored -- that is exactly why guessing is unsafe.)
//
// Build:
//   arduino-cli compile --upload -p <port> --fqbn arduino:renesas_uno:unor4wifi \
//     --library . --build-property "build.extra_flags=-DMADS_ENABLE_CURVE" \
//     test/hardware/curve_bench
#include <MadsUnoAgent.h>
#include "arduino_secrets.h"

#ifndef SECRET_SETTINGS_PORT
#define SECRET_SETTINGS_PORT 9092
#endif

Mads::Agent agent;
JsonDocument doc;

static const int BATCH = 200;

static void report(const char *what, uint32_t total_us, uint32_t max_us,
                   int n) {
  Serial.print("  ");
  Serial.print(what);
  Serial.print(": mean ");
  Serial.print(total_us / (float)n, 1);
  Serial.print(" us, max ");
  Serial.print(max_us);
  Serial.println(" us");
}

static bool g_ready = false;

static const char *curve_err() {
#ifdef MADS_ENABLE_CURVE
  switch (agent.last_curve_error()) {
  case Mads::CurveError::none: return "none";
  case Mads::CurveError::no_entropy: return "no_entropy";
  case Mads::CurveError::greeting: return "greeting (broker not --crypto?)";
  case Mads::CurveError::welcome: return "welcome";
  case Mads::CurveError::mac: return "mac (wrong broker key?)";
  case Mads::CurveError::rejected: return "rejected (key not authorised)";
  case Mads::CurveError::timeout: return "timeout";
  case Mads::CurveError::disconnected: return "disconnected";
  case Mads::CurveError::protocol: return "protocol";
  }
#endif
  return "n/a";
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 3000) {}
#ifdef MADS_ENABLE_CURVE
  if (!agent.set_crypto(SECRET_CURVE_CLIENT_PUBLIC, SECRET_CURVE_CLIENT_SECRET,
                        SECRET_CURVE_BROKER_PUBLIC))
    Serial.println("set_crypto() FAILED -- check the Z85 key lines");
#endif
}

void loop() {
  // Connect (and reconnect) from loop() rather than setup(), and keep
  // saying so. Reporting once at boot and then blocking forever means a
  // terminal attached even a second late sees nothing at all, which is
  // exactly how this sketch wasted a debugging cycle.
  if (!g_ready) {
    Serial.print("connecting to ");
    Serial.print(SECRET_BROKER_HOST);
    Serial.print(":");
#ifdef MADS_ENABLE_CURVE
    Serial.print(SECRET_SETTINGS_PORT);
    const uint16_t port = SECRET_SETTINGS_PORT;
#else
    Serial.print(SECRET_NULL_SETTINGS_PORT);
    const uint16_t port = SECRET_NULL_SETTINGS_PORT;
#endif
    Serial.print(agent.crypto_enabled() ? "  (CURVE)" : "  (plain)");
    Serial.println();
    if (!agent.begin(SECRET_WIFI_SSID, SECRET_WIFI_PASS, SECRET_BROKER_HOST,
                     port, "uno_r4", "bench")) {
      const bool wifi_up = (WiFi.status() == WL_CONNECTED);
      Serial.print("  begin() failed, wifi=");
      Serial.print(wifi_up ? "up" : "down");
      Serial.print(" status=");
      Serial.print(WiFi.status());
      Serial.print(" curve_error=");
      Serial.println(curve_err());
      if (!wifi_up) {
        // Say what the radio can actually see. Guessing at "wrong password"
        // versus "wrong band" versus "not broadcasting" from a failed join
        // is exactly the guesswork this avoids.
        Serial.print("  scanning... ");
        const int n = WiFi.scanNetworks();
        Serial.print(n);
        Serial.println(" networks:");
        for (int i = 0; i < n && i < 12; ++i) {
          Serial.print("    \"");
          Serial.print(WiFi.SSID(i));
          Serial.print("\"  rssi=");
          Serial.print(WiFi.RSSI(i));
          Serial.print(" enc=");
          Serial.println(WiFi.encryptionType(i));
        }
        Serial.print("  looking for: \"");
        Serial.print(SECRET_WIFI_SSID);
        Serial.println("\"");
      }
      // Back off hard between attempts. Re-entering WiFi.begin() every
      // couple of seconds is itself capable of leaving the ESP32
      // unresponsive -- which looks exactly like a wedged board, and was
      // mistaken for one more than once.
      delay(10000);
      return;
    }
    g_ready = true;
    Serial.println("  connected");
    return;
  }

  uint32_t pub_total = 0, pub_max = 0, json_total = 0, json_max = 0;
  int ok = 0;
  const uint32_t wall_start = millis();

  for (int i = 0; i < BATCH; ++i) {
    uint32_t t0 = micros();
    doc.clear();
    doc["a0"] = analogRead(A0);
    doc["i"] = i;
    uint32_t t1 = micros();
    bool good = agent.publish(doc);
    uint32_t t2 = micros();
    const uint32_t jd = t1 - t0, pd = t2 - t1;
    json_total += jd; if (jd > json_max) json_max = jd;
    pub_total += pd;  if (pd > pub_max)  pub_max = pd;
    if (good) ++ok;
  }
  const uint32_t wall = millis() - wall_start;

  uint32_t ser_total = 0, ser_max = 0;
  for (int i = 0; i < 20; ++i) {
    uint32_t t0 = micros();
    Serial.println("published {\"a0\":247,\"agent_id\":\"A0:D2:36:45:3A:B4\","
                   "\"hostname\":\"172.20.10.10\",\"millis\":12052}");
    ser_total += micros() - t0;
    if (micros() - t0 > ser_max) ser_max = micros() - t0;
  }

  Serial.println();
  Serial.print("batch of ");
  Serial.print(BATCH);
  Serial.print(" publishes, ");
  Serial.print(ok);
  Serial.print(" ok, encrypted=");
  Serial.println(agent.crypto_enabled() ? "yes" : "no");
  report("json build ", json_total, json_max, BATCH);
  report("publish()  ", pub_total, pub_max, BATCH);
  report("Serial line", ser_total, ser_max, 20);
  Serial.print("  wall clock: ");
  Serial.print(wall);
  Serial.print(" ms -> ");
  Serial.print(BATCH * 1000.0f / wall, 1);
  Serial.println(" Hz sustained, no Serial in the loop");
  Serial.println();

  if (ok == 0) { g_ready = false; }  // link died -- go back to reconnecting
  delay(1500);
}
