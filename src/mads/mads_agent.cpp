#include "mads_agent.hpp"
#include "zmtp_codec.hpp"
#include <WiFiS3.h>
#include <cstring>

namespace Mads {

Agent::Agent(const char *agent_id) {
  if (agent_id && agent_id[0] != '\0') {
    strncpy(_agent_id, agent_id, sizeof(_agent_id) - 1);
    _agent_id[sizeof(_agent_id) - 1] = '\0';
    _agent_id_explicit = true;
  }
}

bool Agent::begin(const char *ssid, const char *pass, const char *broker_host,
                  uint16_t settings_port, const char *agent_name,
                  const char *pub_topic, uint32_t timeout_ms) {
  _broker_host = broker_host;
  _pub_topic = pub_topic;

  if (WiFi.status() != WL_CONNECTED) {
    WiFi.begin(ssid, pass);
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED) {
      if (millis() - start > timeout_ms)
        return false;
      delay(100);
    }
  }

  // WL_CONNECTED (AP association) can fire before DHCP has actually
  // assigned an IP -- wait explicitly for a real address rather than
  // relying on incidental delays elsewhere (seen failing intermittently
  // during bring-up: WiFi.localIP() still read back 0.0.0.0 otherwise).
  {
    uint32_t start = millis();
    IPAddress ip = WiFi.localIP();
    while (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
      if (millis() - start > timeout_ms)
        return false;
      delay(100);
      ip = WiFi.localIP();
    }
    snprintf(_hostname, sizeof(_hostname), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  }

  if (!_agent_id_explicit) {
    // WiFi.macAddress() fills mac[] in reverse byte order -- a well-known
    // quirk shared by WiFiNINA/WiFiS3, so mac[5] is the first byte printed.
    byte mac[6];
    WiFi.macAddress(mac);
    snprintf(_agent_id, sizeof(_agent_id), "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
  }

  if (!fetch_settings(agent_name, settings_port, timeout_ms))
    return false;

  if (!_pub_transport.connect(_broker_host, _frontend_port))
    return false;
  if (!ZmtpCodec::handshake_null(_pub_transport, "PUB", timeout_ms)) {
    _pub_transport.close();
    return false;
  }
  return true;
}

bool Agent::fetch_settings(const char *agent_name, uint16_t settings_port,
                           uint32_t timeout_ms) {
  WifiTransport settings_transport;
  if (!settings_transport.connect(_broker_host, settings_port))
    return false;
  if (!ZmtpCodec::handshake_null(settings_transport, "REQ", timeout_ms)) {
    settings_transport.close();
    return false;
  }

  // Wire content of a REQ send is actually [""(empty delimiter)][...],
  // invisible at the zmqpp/desktop-Agent level but required at this raw
  // ZMTP layer -- see req.cpp's xsend() in the vendored libzmq source.
  bool sent =
      ZmtpCodec::send_frame(settings_transport, "", true) &&
      ZmtpCodec::send_frame(settings_transport, MADS_LIB_VERSION, true) &&
      ZmtpCodec::send_frame(settings_transport, "settings", true) &&
      ZmtpCodec::send_frame(settings_transport, agent_name, false);
  if (!sent) {
    settings_transport.close();
    return false;
  }

  // Reply: [""][broker_version][raw_ini_text][optional attachment].
  uint8_t flags;
  uint64_t len;

  // Frame 0: empty delimiter.
  if (!ZmtpCodec::recv_frame_header(settings_transport, flags, len, timeout_ms) ||
      !ZmtpCodec::skip_frame_body(settings_transport, len, timeout_ms) ||
      !(flags & ZmtpCodec::FLAG_MORE)) {
    settings_transport.close();
    return false;
  }

  // Frame 1: broker version string (not checked -- the broker itself is
  // the version authority; nothing to gain from validating it here).
  if (!ZmtpCodec::recv_frame_header(settings_transport, flags, len, timeout_ms) ||
      !ZmtpCodec::skip_frame_body(settings_transport, len, timeout_ms) ||
      !(flags & ZmtpCodec::FLAG_MORE)) {
    settings_transport.close();
    return false;
  }

  // Frame 2: the raw ini text -- streamed through TomlScan rather than
  // buffered, since this frame can be several KB (the broker sends its
  // entire settings file to every agent, not a per-agent slice). Watching
  // the agent's own section means the whole frame must be consumed (no
  // early exit once the shared [agents] keys are found), since that
  // section's position in the file isn't known in advance.
  if (!ZmtpCodec::recv_frame_header(settings_transport, flags, len, timeout_ms)) {
    settings_transport.close();
    return false;
  }
  _settings_scan.watch_section(agent_name);
  {
    uint64_t remaining = len;
    uint8_t chunk[32];
    while (remaining > 0) {
      size_t want =
          remaining > sizeof(chunk) ? sizeof(chunk) : static_cast<size_t>(remaining);
      int n = settings_transport.read(chunk, want, timeout_ms);
      if (n <= 0) {
        settings_transport.close();
        return false;
      }
      _settings_scan.feed(chunk, static_cast<size_t>(n));
      remaining -= static_cast<uint64_t>(n);
    }
    _settings_scan.finish();
  }

  // Any further frame (a broker-side attachment) is drained and discarded --
  // this library has no use for it.
  while (flags & ZmtpCodec::FLAG_MORE) {
    if (!ZmtpCodec::recv_frame_header(settings_transport, flags, len, timeout_ms))
      break;
    if (!ZmtpCodec::skip_frame_body(settings_transport, len, timeout_ms))
      break;
  }

  settings_transport.close();

  if (!_settings_scan.done() || _settings_scan.frontend_port() == 0 ||
      _settings_scan.backend_port() == 0)
    return false;

  _frontend_port = _settings_scan.frontend_port();
  _backend_port = _settings_scan.backend_port();
  _timecode_fps =
      _settings_scan.timecode_fps() > 0 ? _settings_scan.timecode_fps() : 25;
  return true;
}

bool Agent::connect_sub(uint32_t timeout_ms) {
  if (!_broker_host)
    return false;
  if (!_sub_transport.connect(_broker_host, _backend_port))
    return false;
  if (!ZmtpCodec::handshake_null(_sub_transport, "SUB", timeout_ms)) {
    _sub_transport.close();
    return false;
  }
  _sub_connected = true;
  return true;
}

bool Agent::subscribe(const char *topic) {
  if (!_sub_connected)
    return false;
  return ZmtpCodec::send_subscription(_sub_transport, topic, true);
}

bool Agent::publish(const char *json, size_t json_len, const char *topic) {
  if (!_pub_transport.connected())
    return false;
  const char *use_topic = topic ? topic : _pub_topic;

  // The MADS wire header (src/agent.cpp in the main MADS repo): "MADS" +
  // version(1) + format(1) + compression(1) + flags(1) + 4-byte schema.
  // format=0 (Json), compression=0 (None) -- the only combination this
  // library supports send- and receive-side. A bare 2-part [topic][payload]
  // frame is always read by real MADS peers as snappy-compressed, so this
  // 3-part header form is the only way to interoperate as plain JSON.
  uint8_t header[12] = {'M', 'A', 'D', 'S', 1, 0, 0, 0, 0, 0, 0, 0};

  return ZmtpCodec::send_frame(_pub_transport,
                               reinterpret_cast<const uint8_t *>(use_topic),
                               strlen(use_topic), true) &&
         ZmtpCodec::send_frame(_pub_transport, header, sizeof(header), true) &&
         ZmtpCodec::send_frame(_pub_transport,
                               reinterpret_cast<const uint8_t *>(json),
                               json_len, false);
}

bool Agent::publish(JsonDocument &payload, const char *topic) {
  payload["agent_id"] = _agent_id;
  payload["hostname"] = _hostname;
  payload["millis"] = millis();

  size_t len = serializeJson(payload, _publish_buf, sizeof(_publish_buf));
  if (len == 0)
    return false;
  return publish(_publish_buf, len, topic);
}

bool Agent::poll(char *topic_out, size_t topic_cap, uint8_t *payload_out,
                 size_t payload_cap, size_t &payload_len, uint32_t timeout_ms) {
  payload_len = 0;
  if (!_sub_connected || !_sub_transport.available())
    return false;

  uint8_t flags;
  uint64_t len;

  // Frame 0: topic.
  if (!ZmtpCodec::recv_frame_header(_sub_transport, flags, len, timeout_ms))
    return false;
  if (len >= topic_cap) {
    ZmtpCodec::skip_frame_body(_sub_transport, len, timeout_ms);
    return false;
  }
  if (!ZmtpCodec::recv_frame_body(_sub_transport,
                                  reinterpret_cast<uint8_t *>(topic_out),
                                  topic_cap, len, timeout_ms))
    return false;
  topic_out[len] = '\0';
  if (!(flags & ZmtpCodec::FLAG_MORE))
    return false; // malformed: expected header+payload frames to follow

  // Frame 1: the 12-byte MADS header.
  if (!ZmtpCodec::recv_frame_header(_sub_transport, flags, len, timeout_ms))
    return false;
  uint8_t header[12];
  if (len != sizeof(header) ||
      !ZmtpCodec::recv_frame_body(_sub_transport, header, sizeof(header), len,
                                  timeout_ms)) {
    // Not our 3-part header form (e.g. legacy 2-part snappy, or a peer
    // publishing MsgPack) -- unsupported by this minimal client, drop it.
    return false;
  }
  if (header[0] != 'M' || header[1] != 'A' || header[2] != 'D' ||
      header[3] != 'S')
    return false;
  if (header[5] != 0 || header[6] != 0)
    return false; // only format=Json, compression=None are supported
  if (!(flags & ZmtpCodec::FLAG_MORE))
    return false;

  // Frame 2: payload.
  if (!ZmtpCodec::recv_frame_header(_sub_transport, flags, len, timeout_ms))
    return false;
  if (len > payload_cap) {
    ZmtpCodec::skip_frame_body(_sub_transport, len, timeout_ms);
    return false;
  }
  if (!ZmtpCodec::recv_frame_body(_sub_transport, payload_out, payload_cap, len,
                                  timeout_ms))
    return false;
  payload_len = static_cast<size_t>(len);
  return true;
}

} // namespace Mads
