// Matches this repo's own mads.ini [uno_r4] section:
//   [uno_r4]
//   ai = [0, 2, 4]     -- analog pins to sample
//   di = [7, 9, 10]    -- digital pins to sample
//   delay = 100        -- main loop delay, in ms
//
// Pin lists and loop delay come from the broker's settings reply, not from
// this sketch, so they can be changed by editing mads.ini without
// reflashing the board. agent_id/hostname/millis are added automatically by
// agent.publish(doc) -- see Mads::Agent's class doc.
//
// No need to #include <ArduinoJson.h> here -- MadsUnoAgent.h already pulls
// it in (Agent::publish(JsonDocument&) depends on it directly).
#include <MadsUnoAgent.h>
#include "arduino_secrets.h" // copy from arduino_secrets.h.example, gitignored

const char *WIFI_SSID = SECRET_WIFI_SSID;
const char *WIFI_PASS = SECRET_WIFI_PASS;
const char *BROKER_HOST = SECRET_BROKER_HOST;
const uint16_t SETTINGS_PORT = 9092; // mads.ini [broker] settings_address port
const char *AGENT_NAME = "uno_r4";    // must match the ini section name

Mads::Agent agent;
JsonDocument doc;

const size_t MAX_PINS = 8;
int ai_pins[MAX_PINS];
int di_pins[MAX_PINS];
size_t ai_count = 0;
size_t di_count = 0;
int loop_delay_ms = 100;

void setup() {
  Serial.begin(115200);
  delay(2000); // give the serial monitor time to attach after reset

  Serial.println("Joining WiFi + fetching MADS settings...");
  bool ok = agent.begin(WIFI_SSID, WIFI_PASS, BROKER_HOST, SETTINGS_PORT,
                        AGENT_NAME, AGENT_NAME);
  if (!ok) {
    Serial.println("MADS agent begin() failed");
    return;
  }

  ai_count = agent.setting_int_array("ai", ai_pins, MAX_PINS);
  di_count = agent.setting_int_array("di", di_pins, MAX_PINS);
  loop_delay_ms = agent.setting_int("delay", 100);

  for (size_t i = 0; i < di_count; ++i)
    pinMode(di_pins[i], INPUT);

  Serial.print("MADS agent ready: agent_id=");
  Serial.print(agent.agent_id());
  Serial.print(" hostname=");
  Serial.print(agent.hostname());
  Serial.print(" frontend_port=");
  Serial.print(agent.frontend_port());
  Serial.print(" backend_port=");
  Serial.print(agent.backend_port());
  Serial.print(" ai_count=");
  Serial.print(ai_count);
  Serial.print(" di_count=");
  Serial.print(di_count);
  Serial.print(" delay_ms=");
  Serial.println(loop_delay_ms);
}

void loop() {
  doc.clear();
  JsonArray ai = doc["ai"].to<JsonArray>();
  for (size_t i = 0; i < ai_count; ++i)
    ai.add(analogRead(ai_pins[i]));
  JsonArray di = doc["di"].to<JsonArray>();
  for (size_t i = 0; i < di_count; ++i)
    di.add(digitalRead(di_pins[i]));

  bool ok = agent.publish(doc);
  Serial.print(ok ? "published " : "publish FAILED ");
  Serial.println(agent.last_publish_json());

  delay(loop_delay_ms);
}
