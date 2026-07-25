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
// The link self-heals: if the broker goes away, publish() fails and the
// agent retries in the background (once per reconnect interval) until it
// is reachable again. Settings are (re)fetched as part of that, so this
// sketch also survives being powered on before the broker exists -- hence
// the settings_ok() check in loop() rather than a hard bail in setup().
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
bool pins_loaded = false;
bool was_connected = false;

void load_pin_settings() {
  ai_count = agent.setting_int_array("ai", ai_pins, MAX_PINS);
  di_count = agent.setting_int_array("di", di_pins, MAX_PINS);
  loop_delay_ms = agent.setting_int("delay", 100);

  for (size_t i = 0; i < di_count; ++i)
    pinMode(di_pins[i], INPUT);

  pins_loaded = true;
  Serial.print("settings loaded: agent_id=");
  Serial.print(agent.agent_id());
  Serial.print(" hostname=");
  Serial.print(agent.hostname());
  Serial.print(" ai_count=");
  Serial.print(ai_count);
  Serial.print(" di_count=");
  Serial.print(di_count);
  Serial.print(" delay_ms=");
  Serial.println(loop_delay_ms);
}

void setup() {
  Serial.begin(115200);
  delay(2000); // give the serial monitor time to attach after reset

  agent.set_reconnect_interval(1000); // retry a dead link once a second

  Serial.println("Joining WiFi + fetching MADS settings...");
  if (agent.begin(WIFI_SSID, WIFI_PASS, BROKER_HOST, SETTINGS_PORT, AGENT_NAME,
                  AGENT_NAME)) {
    load_pin_settings();
    was_connected = true;
    Serial.println("MADS agent ready");
  } else {
    // Not fatal: loop() keeps retrying, so the board can boot before the broker.
    Serial.println("MADS agent begin() failed -- will keep retrying");
  }
}

void loop() {
  if (!pins_loaded && agent.settings_ok())
    load_pin_settings();

  doc.clear();
  JsonArray ai = doc["ai"].to<JsonArray>();
  for (size_t i = 0; i < ai_count; ++i)
    ai.add(analogRead(ai_pins[i]));
  JsonArray di = doc["di"].to<JsonArray>();
  for (size_t i = 0; i < di_count; ++i)
    di.add(digitalRead(di_pins[i]));

  bool ok = agent.publish(doc);
  if (ok != was_connected) { // report only the transitions, not every loop
    Serial.println(ok ? "link UP: publishing" : "link DOWN: reconnecting...");
    was_connected = ok;
  }
  if (ok) {
    Serial.print("published ");
    Serial.println(agent.last_publish_json());
  }

  delay(loop_delay_ms);
}
