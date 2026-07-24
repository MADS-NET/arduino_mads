// Matches this repo's own mads.ini [uno_r4] section:
//   [uno_r4]
//   ai = [0, 2, 4]     -- analog pins to sample
//   di = [7, 9, 10]    -- digital pins to sample
//   delay = 100        -- main loop delay, in ms
//
// Pin lists and loop delay come from the broker's settings reply, not from
// this sketch, so they can be changed by editing mads.ini without
// reflashing the board.
#include <MadsUnoAgent.h>

const char *WIFI_SSID = "your-ssid";
const char *WIFI_PASS = "your-password";
const char *BROKER_HOST = "192.168.1.10"; // the mads-broker's IP
const uint16_t SETTINGS_PORT = 9092;      // mads.ini [broker] settings_address port
const char *AGENT_NAME = "uno_r4";        // must match the ini section name

Mads::Agent agent;
char json_buf[192];

const size_t MAX_PINS = 8;
int ai_pins[MAX_PINS];
int di_pins[MAX_PINS];
size_t ai_count = 0;
size_t di_count = 0;
int loop_delay_ms = 100;

void setup() {
  Serial.begin(115200);
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

  Serial.println("MADS agent ready");
}

void loop() {
  size_t pos = 0;
  pos += snprintf(json_buf + pos, sizeof(json_buf) - pos, "{\"ai\":[");
  for (size_t i = 0; i < ai_count; ++i)
    pos += snprintf(json_buf + pos, sizeof(json_buf) - pos, "%s%d",
                    i ? "," : "", analogRead(ai_pins[i]));
  pos += snprintf(json_buf + pos, sizeof(json_buf) - pos, "],\"di\":[");
  for (size_t i = 0; i < di_count; ++i)
    pos += snprintf(json_buf + pos, sizeof(json_buf) - pos, "%s%d",
                    i ? "," : "", digitalRead(di_pins[i]));
  pos += snprintf(json_buf + pos, sizeof(json_buf) - pos, "]}");

  agent.publish(json_buf, pos);
  delay(loop_delay_ms);
}
