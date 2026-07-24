// MADS agent that both publishes and subscribes: publishes an analog
// reading, and polls non-blockingly for messages on the "control" topic.
#include <MadsUnoAgent.h>
#include "arduino_secrets.h" // copy from arduino_secrets.h.example, gitignored

const char *WIFI_SSID = SECRET_WIFI_SSID;
const char *WIFI_PASS = SECRET_WIFI_PASS;
const char *BROKER_HOST = SECRET_BROKER_HOST;
const uint16_t SETTINGS_PORT = 9092; // mads.ini [broker] settings_address port

Mads::Agent agent;
char json_buf[128];
char topic_buf[32];
uint8_t payload_buf[128];

void setup() {
  Serial.begin(115200);
  bool ok = agent.begin(WIFI_SSID, WIFI_PASS, BROKER_HOST, SETTINGS_PORT,
                        "uno_r4", "sensors");
  if (ok) {
    agent.connect_sub();
    agent.subscribe("control");
  }
  Serial.println(ok ? "MADS agent ready" : "MADS agent begin() failed");
}

void loop() {
  int value = analogRead(A0);
  size_t len = snprintf(json_buf, sizeof(json_buf), "{\"a0\":%d}", value);
  agent.publish(json_buf, len);

  size_t payload_len;
  if (agent.poll(topic_buf, sizeof(topic_buf), payload_buf, sizeof(payload_buf),
                 payload_len)) {
    Serial.print("recv ");
    Serial.print(topic_buf);
    Serial.print(": ");
    Serial.write(payload_buf, payload_len);
    Serial.println();
  }

  delay(200);
}
