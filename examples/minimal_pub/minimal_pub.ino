// Minimal MADS agent: publishes an analog reading once per loop iteration.
// No subscription -- this is the smallest useful shape (setup() fetches
// settings and opens the PUB connection; loop() only publishes).
//
// No need to #include <ArduinoJson.h> here -- MadsUnoAgent.h already pulls
// it in (Agent::publish(JsonDocument&) depends on it directly).
#include <MadsUnoAgent.h>
#include "arduino_secrets.h" // copy from arduino_secrets.h.example, gitignored

const char *WIFI_SSID = SECRET_WIFI_SSID;
const char *WIFI_PASS = SECRET_WIFI_PASS;
const char *BROKER_HOST = SECRET_BROKER_HOST;
const uint16_t SETTINGS_PORT = 9092; // mads.ini [broker] settings_address port

Mads::Agent agent;
JsonDocument doc;

void setup() {
  Serial.begin(115200);
  bool ok = agent.begin(WIFI_SSID, WIFI_PASS, BROKER_HOST, SETTINGS_PORT,
                        "uno_r4", "sensors");
  Serial.println(ok ? "MADS agent ready" : "MADS agent begin() failed");
}

void loop() {
  doc.clear();
  doc["a0"] = analogRead(A0);

  // agent_id/hostname/millis are added automatically -- see Mads::Agent's class doc.
  bool ok = agent.publish(doc);
  Serial.print(ok ? "published " : "publish FAILED ");
  Serial.println(agent.last_publish_json());

  delay(200);
}
