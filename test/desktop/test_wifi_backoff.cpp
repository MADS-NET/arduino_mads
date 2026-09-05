// WiFi association is rate-limited separately from broker reconnection.
//
// The bug this guards against is not a crash: it is the library calling
// WiFi.begin() every second or two while a join keeps failing, which
// restarts an association already in flight and can leave the ESP32 module
// unresponsive -- at which point the board stops scanning, stops
// connecting, and (because uploading is serviced by the running sketch's
// USB stack) may not even be reflashable without unplugging it.
//
// Needs no broker: with WiFi down, ensure_pub_link() returns before it ever
// reaches the network.
#include "mads_agent.hpp"

#include <cstdio>
#include <cstring>

static int g_checks = 0;
static int g_failures = 0;
static void check(bool ok, const char *what) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::fprintf(stderr, "  FAIL: %s\n", what);
  }
}

int main() {
  Mads::Agent agent("wifi_backoff_probe");
  // Small numbers so the test runs in a second; the shape is what matters.
  agent.set_reconnect_interval(20);
  agent.set_wifi_backoff_max(200);
  check(agent.wifi_backoff() == 20,
        "set_reconnect_interval() seeds the WiFi backoff");

  WiFiClass::force_down = true;
  WiFiClass::begin_calls = 0;

  // A short timeout keeps each failed association brief.
  agent.begin("ssid", "pass", "127.0.0.1", 9092, "probe", "topic", 30);
  check(WiFiClass::begin_calls == 1,
        "the first attempt is never delayed -- begin() tries immediately");
  check(agent.wifi_backoff() == 40, "a failed join doubles the backoff");

  // Now hammer it the way a sketch does: publish and poll every pass.
  const uint32_t t0 = millis();
  int calls_to_publish = 0;
  char topic[32];
  uint8_t payload[64];
  size_t len = 0;
  JsonDocument doc;
  while (millis() - t0 < 1200) {
    doc.clear();
    doc["v"] = 1;
    agent.publish(doc);
    agent.poll(topic, sizeof(topic), payload, sizeof(payload), len, 0);
    ++calls_to_publish;
  }
  const int begins = WiFiClass::begin_calls;
  std::printf("  %d publish/poll rounds over 1.2 s -> %d WiFi.begin() calls, "
              "backoff now %u ms\n",
              calls_to_publish, begins, agent.wifi_backoff());

  check(agent.wifi_backoff() == 200, "the backoff saturates at its maximum");

  // The real assertion. Each round offers two chances to re-enter
  // WiFi.begin() (the publish path and the poll path). Sharing one attempt
  // clock and backing off should hold it to a handful over 1.2 s; without
  // that it tracks the reconnect interval and the round count.
  check(begins <= 12,
        "WiFi.begin() is called a handful of times, not once per round");
  check(begins < calls_to_publish,
        "WiFi.begin() is not re-entered on every publish");

  // And it must recover: a successful association resets the backoff, or a
  // board that once had a bad minute stays slow forever.
  WiFiClass::force_down = false;
  // Publish for a moment: ensure_pub_link() is itself rate-limited, so one
  // call may return before ever reaching ensure_wifi().
  const uint32_t t1 = millis();
  while (millis() - t1 < 100) {
    doc.clear();
    doc["v"] = 2;
    agent.publish(doc);
  }
  check(agent.wifi_backoff() == 20,
        "a successful association resets the backoff");

  std::printf("test_wifi_backoff: %d checks, %d failures\n", g_checks,
              g_failures);
  return g_failures ? 1 : 0;
}
