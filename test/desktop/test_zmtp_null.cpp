// Live test against a real mads-broker (NULL mechanism). Skipped cleanly --
// exit 0, no assertions run -- unless MADS_BROKER_HOST is set, since this
// environment has no broker to talk to. Run it against a real one with:
//
//   MADS_BROKER_HOST=127.0.0.1 ./test_zmtp_null
//
// and, in another terminal, `mads echo --jsonl` on the same broker to watch
// the published message decode. Optional env vars:
//   MADS_SETTINGS_PORT  (default 9092)
//   MADS_AGENT_NAME     (default "test_agent" -- need not have its own
//                        mads.ini section; fetch_settings() only requires
//                        the shared [agents] keys to succeed)
//   MADS_PUB_TOPIC      (default "test_zmtp_null")
//
// Exercises Agent::begin() (WiFi join is a no-op on the desktop stub, so
// this is really "settings REQ/REP + PUB handshake over a real TCP socket")
// and a JSON publish -- deliberately going through the public Agent API
// rather than ZmtpCodec/ZmtpSession directly, so this test keeps working
// unchanged across the Phase 1 refactor.
#include "mads_agent.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

int main() {
  const char *host = std::getenv("MADS_BROKER_HOST");
  if (!host || host[0] == '\0') {
    std::printf("test_zmtp_null: SKIPPED (MADS_BROKER_HOST not set)\n");
    return 0;
  }

  const char *settings_port_env = std::getenv("MADS_SETTINGS_PORT");
  uint16_t settings_port =
      settings_port_env ? static_cast<uint16_t>(std::atoi(settings_port_env))
                         : 9092;
  const char *agent_name = std::getenv("MADS_AGENT_NAME");
  if (!agent_name || agent_name[0] == '\0')
    agent_name = "test_agent";
  const char *pub_topic = std::getenv("MADS_PUB_TOPIC");
  if (!pub_topic || pub_topic[0] == '\0')
    pub_topic = "test_zmtp_null";

  Mads::Agent agent("desktop_test_zmtp_null");

  std::printf("test_zmtp_null: connecting to %s:%u ...\n", host,
              settings_port);
  bool ok = agent.begin("desktop-ssid-unused", "desktop-pass-unused", host,
                        settings_port, agent_name, pub_topic, 5000);
  if (!ok) {
    std::fprintf(stderr,
                 "test_zmtp_null: FAILED -- begin() returned false "
                 "(settings_ok=%d)\n",
                 agent.settings_ok());
    return 1;
  }
  std::printf("test_zmtp_null: begin() OK -- frontend_port=%u "
              "backend_port=%u timecode_fps=%d\n",
              agent.frontend_port(), agent.backend_port(),
              agent.timecode_fps());

  JsonDocument doc;
  doc["source"] = "test_zmtp_null";
  doc["value"] = 42;
  if (!agent.publish(doc)) {
    std::fprintf(stderr, "test_zmtp_null: FAILED -- publish() returned "
                         "false\n");
    return 1;
  }
  std::printf("test_zmtp_null: publish() OK -- sent: %s\n",
              agent.last_publish_json());

  // Round-trip: also exercise the SUB/poll() path by subscribing to our own
  // topic and republishing a second message, matching the mads broker's
  // usual XSUB->XPUB relay of every PUB'd frame to interested SUBs.
  if (!agent.subscribe(pub_topic)) {
    std::fprintf(stderr, "test_zmtp_null: FAILED -- subscribe() returned "
                         "false\n");
    return 1;
  }
  if (!agent.connect_sub(5000)) {
    std::fprintf(stderr, "test_zmtp_null: FAILED -- connect_sub() returned "
                         "false\n");
    return 1;
  }

  JsonDocument doc2;
  doc2["source"] = "test_zmtp_null";
  doc2["value"] = 43;
  if (!agent.publish(doc2)) {
    std::fprintf(stderr, "test_zmtp_null: FAILED -- second publish() "
                         "returned false\n");
    return 1;
  }

  char topic_buf[64];
  uint8_t payload_buf[512];
  size_t payload_len = 0;
  bool got = false;
  for (int i = 0; i < 25 && !got; ++i) { // up to ~5s at 200ms/poll
    got = agent.poll(topic_buf, sizeof(topic_buf), payload_buf,
                     sizeof(payload_buf), payload_len, 200);
  }
  if (!got) {
    std::fprintf(stderr,
                 "test_zmtp_null: FAILED -- poll() never received the "
                 "republished message\n");
    return 1;
  }
  std::printf("test_zmtp_null: poll() OK -- topic=%s payload=%.*s\n",
              topic_buf, static_cast<int>(payload_len),
              reinterpret_cast<char *>(payload_buf));

  std::printf("test_zmtp_null: PASSED\n");
  return 0;
}
