// Minimal MADS agent: publishes an analog reading once per loop iteration.
// No subscription -- this is the smallest useful shape (setup() fetches
// settings and opens the PUB connection; loop() only publishes).
#include <MadsUnoAgent.h>

const char *WIFI_SSID = "your-ssid";
const char *WIFI_PASS = "your-password";
const char *BROKER_HOST = "192.168.1.10"; // the mads-broker's IP
const uint16_t SETTINGS_PORT = 9092;      // mads.ini [broker] settings_address port

Mads::Agent agent;
char json_buf[128];

void setup() {
  Serial.begin(115200);
  bool ok = agent.begin(WIFI_SSID, WIFI_PASS, BROKER_HOST, SETTINGS_PORT,
                        "uno_r4", "sensors");
  Serial.println(ok ? "MADS agent ready" : "MADS agent begin() failed");
}

void loop() {
  int value = analogRead(A0);
  size_t len = snprintf(json_buf, sizeof(json_buf), "{\"a0\":%d}", value);
  agent.publish(json_buf, len);
  delay(200);
}
