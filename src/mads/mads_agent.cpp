#include "mads_agent.hpp"
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
  _ssid = ssid;
  _pass = pass;
  _broker_host = broker_host;
  _pub_topic = pub_topic;
  _agent_name = agent_name;
  _settings_port = settings_port;
  _timeout_ms = timeout_ms;

  if (!ensure_wifi(timeout_ms))
    return false;
  if (!fetch_settings(timeout_ms))
    return false;

  if (!_pub_transport.connect(_broker_host, _frontend_port))
    return false;
  _pub_session.reset();
  arm_session(_pub_session);
  if (!_pub_session.handshake("PUB", timeout_ms)) {
    _pub_transport.close();
    note_handshake_failure();
    return false;
  }
  note_handshake_success();
  _last_pub_connect = millis();
  _pub_assumed_up = true;
  _last_link_check = millis();
  return true;
}

bool Agent::ensure_wifi(uint32_t timeout_ms) {
  if (WiFi.status() != WL_CONNECTED) {
    // Rate-limit the association attempt itself. Calling WiFi.begin() again
    // while one is already in flight restarts it, and doing that every
    // second or two can leave the module unresponsive -- see
    // Agent::wifi_backoff(). _wifi_attempted lets the very first call
    // through, so begin() is never delayed at startup.
    const uint32_t now = millis();
    if (_wifi_attempted && (now - _last_wifi_attempt) < _wifi_backoff_ms)
      return false;
    _wifi_attempted = true;
    _last_wifi_attempt = now;

    WiFi.begin(_ssid, _pass);
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED) {
      if (millis() - start > timeout_ms) {
        // Back off before touching the radio again.
        const uint32_t doubled = _wifi_backoff_ms * 2;
        _wifi_backoff_ms = (doubled > _wifi_backoff_max_ms ||
                            doubled < _wifi_backoff_ms)
                               ? _wifi_backoff_max_ms
                               : doubled;
        return false;
      }
      delay(100);
    }
  }

  // Reached whenever the radio is associated -- whether we just joined, or
  // it came back on its own while we were backed off. Resetting only after
  // *our* successful begin() would leave a board that recovered by itself
  // permanently slow to react to the next drop.
  reset_wifi_backoff();

  // WL_CONNECTED (AP association) can fire before DHCP has actually
  // assigned an IP -- wait explicitly for a real address rather than
  // relying on incidental delays elsewhere (seen failing intermittently
  // during bring-up: WiFi.localIP() still read back 0.0.0.0 otherwise).
  // Re-read on every rejoin: DHCP may hand out a different address.
  uint32_t start = millis();
  IPAddress ip = WiFi.localIP();
  while (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
    if (millis() - start > timeout_ms)
      return false;
    delay(100);
    ip = WiFi.localIP();
  }
  snprintf(_hostname, sizeof(_hostname), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

  if (!_agent_id_explicit && _agent_id[0] == '\0') {
    // WiFi.macAddress() fills mac[] in reverse byte order -- a well-known
    // quirk shared by WiFiNINA/WiFiS3, so mac[5] is the first byte printed.
    byte mac[6];
    WiFi.macAddress(mac);
    snprintf(_agent_id, sizeof(_agent_id), "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
  }
  return true;
}

size_t Agent::drain_pub() {
  size_t total = 0;
  uint8_t scratch[64];
  // Bounded: a peer that streams at us must not be able to hold loop()
  // here. Anything left over is drained on the next pass.
  for (int i = 0; i < 16 && _pub_transport.available(); ++i) {
    const int n = _pub_transport.read(scratch, sizeof(scratch), 0);
    if (n <= 0)
      break;
    total += static_cast<size_t>(n);
  }
  return total;
}

bool Agent::ensure_pub_link() {
  // Probing liveness costs ~9.6 ms -- a round-trip to the ESP32, and about a
  // third of a publish. Between probes, assume the link we last saw up is
  // still up: a broken one is still caught by a failed write, and by the
  // refresh timer below. Nothing is given up here that connected() reliably
  // provided, because it does not reliably provide it.
  const uint32_t now_ms = millis();
  bool up;
  if (_pub_assumed_up && _link_check_ms != 0 &&
      (now_ms - _last_link_check) < _link_check_ms) {
    up = true;
  } else {
    up = _pub_transport.connected();
    _last_link_check = now_ms;
    _pub_assumed_up = up;
  }

  if (up) {
    // "Connected" is not trustworthy here: after a broker restart the ESP32
    // keeps reporting this socket as established and keeps accepting
    // writes, indefinitely, while nothing is delivered. A PUB socket gets
    // no reply traffic, so there is no timeout to hang a watchdog on --
    // rebuilding the link on a timer is the only reliable defence. See
    // Agent::set_pub_refresh_interval().
    if (_pub_refresh_ms == 0 ||
        (millis() - _last_pub_connect) < _pub_refresh_ms)
      return true;
    _pub_transport.close();
    _pub_assumed_up = false;
  }
  if (!_broker_host)
    return false;

  // Rate-limit: at most one attempt per interval. _pub_attempted guards the
  // very first call, where a zero _last_pub_attempt would otherwise be
  // indistinguishable from "just tried" during the first interval after boot.
  uint32_t now = millis();
  // retry_interval() is reconnect_interval() until a CURVE handshake is
  // *rejected*, which is deterministic, costs ~180 ms of X25519 per attempt,
  // and never self-heals -- see Agent::curve_backoff().
  if (_pub_attempted && (now - _last_pub_attempt) < retry_interval())
    return false;
  _pub_attempted = true;
  _last_pub_attempt = now;

  _pub_transport.close();
  if (!ensure_wifi(_timeout_ms))
    return false;
  // Covers the broker having been unreachable when begin() ran: without
  // valid settings we don't know the real frontend port yet.
  if (!_settings_ok && !fetch_settings(_timeout_ms))
    return false;
  // A failed connect is the cheap, self-healing "broker not up yet" case and
  // deliberately does not touch the backoff.
  if (!_pub_transport.connect(_broker_host, _frontend_port))
    return false;
  _pub_session.reset();
  arm_session(_pub_session);
  if (!_pub_session.handshake("PUB", _timeout_ms)) {
    _pub_transport.close();
    note_handshake_failure();
    return false;
  }
  note_handshake_success();
  _last_pub_connect = millis();
  _pub_assumed_up = true;
  _last_link_check = millis();
  return true;
}

bool Agent::ensure_sub_link() {
  if (_sub_transport.connected())
    return true;
  if (!_broker_host)
    return false;

  uint32_t now = millis();
  if (_sub_attempted && (now - _last_sub_attempt) < retry_interval())
    return false;
  _sub_attempted = true;
  _last_sub_attempt = now;

  _sub_transport.close();
  if (!ensure_wifi(_timeout_ms))
    return false;
  if (!_settings_ok && !fetch_settings(_timeout_ms))
    return false;
  if (!_sub_transport.connect(_broker_host, _backend_port))
    return false;
  _sub_session.reset();
  arm_session(_sub_session);
  if (!_sub_session.handshake("SUB", _timeout_ms)) {
    _sub_transport.close();
    note_handshake_failure();
    return false;
  }

  // ZMTP subscriptions are per-connection state: a fresh socket has none,
  // so every remembered topic must be re-sent or this link would go silent.
  for (size_t i = 0; i < _sub_topic_count; ++i) {
    if (!_sub_session.send_subscription(_sub_topics[i], true)) {
      _sub_transport.close();
      return false;
    }
  }
  _last_sub_rx = millis();
  note_handshake_success();
  return true;
}

bool Agent::fetch_settings(uint32_t timeout_ms) {
  const char *agent_name = _agent_name;
  // A scanner that already consumed one reply would otherwise append
  // duplicate watched-section entries and report done() from the old run.
  _settings_scan.reset();
  _settings_ok = false;

  WifiTransport settings_transport;
  if (!settings_transport.connect(_broker_host, _settings_port))
    return false;
  ZmtpSession session(settings_transport);
  session.reset();
  // The settings ROUTER gets CURVE too (broker.cpp binds all three sockets
  // with it), so there is no unencrypted bootstrap: begin() cannot read
  // mads.ini at all until a handshake has completed.
  arm_session(session);
  if (!session.handshake("REQ", timeout_ms)) {
    settings_transport.close();
    note_handshake_failure();
    return false;
  }
  note_handshake_success();

  // Wire content of a REQ send is actually [""(empty delimiter)][...],
  // invisible at the zmqpp/desktop-Agent level but required at this raw
  // ZMTP layer -- see req.cpp's xsend() in the vendored libzmq source.
  bool sent =
      session.send_frame("", true) &&
      session.send_frame(MADS_LIB_VERSION, true) &&
      session.send_frame("settings", true) &&
      session.send_frame(agent_name, false);
  if (!sent) {
    settings_transport.close();
    return false;
  }

  // Reply: [""][broker_version][raw_ini_text][optional attachment].
  uint8_t flags;
  uint64_t len;

  // Frame 0: empty delimiter.
  if (!session.recv_frame_header(flags, len, timeout_ms) ||
      !session.skip_frame_body(len, timeout_ms) ||
      !(flags & ZmtpSession::FLAG_MORE)) {
    settings_transport.close();
    return false;
  }

  // Frame 1: broker version string (not checked -- the broker itself is
  // the version authority; nothing to gain from validating it here).
  if (!session.recv_frame_header(flags, len, timeout_ms) ||
      !session.skip_frame_body(len, timeout_ms) ||
      !(flags & ZmtpSession::FLAG_MORE)) {
    settings_transport.close();
    return false;
  }

  // Frame 2: the raw ini text -- streamed through TomlScan rather than
  // buffered, since this frame can be several KB (the broker sends its
  // entire settings file to every agent, not a per-agent slice). Watching
  // the agent's own section means the whole frame must be consumed (no
  // early exit once the shared [agents] keys are found), since that
  // section's position in the file isn't known in advance.
  //
  // Streamed through the begin_recv_body/read_body_chunk/end_recv_body
  // trio rather than a raw transport.read() loop: under CURVE (not enabled
  // here) the plaintext is delivered before it is authenticated, so a
  // false from end_recv_body() means the whole chunk stream must be
  // discarded -- which is why _settings_scan.reset() runs on that path
  // below, even though under NULL end_recv_body() always returns true and
  // this is a no-op today.
  if (!session.recv_frame_header(flags, len, timeout_ms)) {
    settings_transport.close();
    return false;
  }
  _settings_scan.watch_section(agent_name);
  {
    if (!session.begin_recv_body(len)) {
      settings_transport.close();
      return false;
    }
    uint64_t remaining = len;
    uint8_t chunk[32];
    while (remaining > 0) {
      size_t want =
          remaining > sizeof(chunk) ? sizeof(chunk) : static_cast<size_t>(remaining);
      int n = session.read_body_chunk(chunk, want, timeout_ms);
      if (n <= 0) {
        settings_transport.close();
        return false;
      }
      _settings_scan.feed(chunk, static_cast<size_t>(n));
      remaining -= static_cast<uint64_t>(n);
    }
    if (!session.end_recv_body()) {
      _settings_scan.reset();
      settings_transport.close();
      return false;
    }
    _settings_scan.finish();
  }

  // Any further frame (a broker-side attachment) is drained and discarded --
  // this library has no use for it.
  while (flags & ZmtpSession::FLAG_MORE) {
    if (!session.recv_frame_header(flags, len, timeout_ms))
      break;
    if (!session.skip_frame_body(len, timeout_ms))
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
  _settings_ok = true;
  return true;
}

bool Agent::connect_sub(uint32_t timeout_ms) {
  _want_sub = true;
  if (!_broker_host)
    return false;
  if (!_sub_transport.connect(_broker_host, _backend_port))
    return false;
  _sub_session.reset();
  arm_session(_sub_session);
  if (!_sub_session.handshake("SUB", timeout_ms)) {
    _sub_transport.close();
    note_handshake_failure();
    return false;
  }
  note_handshake_success();
  for (size_t i = 0; i < _sub_topic_count; ++i) {
    if (!_sub_session.send_subscription(_sub_topics[i], true)) {
      _sub_transport.close();
      return false;
    }
  }
  _last_sub_rx = millis();
  return true;
}

bool Agent::subscribe(const char *topic) {
  if (!topic)
    return false;
  _want_sub = true;

  // Remember it first: the link may be down now, and every reconnect has to
  // replay the full set (ZMTP subscriptions don't survive a new socket).
  bool known = false;
  for (size_t i = 0; i < _sub_topic_count; ++i)
    if (strcmp(_sub_topics[i], topic) == 0)
      known = true;
  if (!known) {
    if (_sub_topic_count >= MAX_SUB_TOPICS)
      return false; // no room to remember it, so don't pretend it's durable
    strncpy(_sub_topics[_sub_topic_count], topic, SUB_TOPIC_CAP - 1);
    _sub_topics[_sub_topic_count][SUB_TOPIC_CAP - 1] = '\0';
    ++_sub_topic_count;
  }

  if (!_sub_transport.connected())
    return false; // stored; ensure_sub_link() will send it once up
  return _sub_session.send_subscription(topic, true);
}

bool Agent::publish(const char *json, size_t json_len, const char *topic) {
  if (!ensure_pub_link())
    return false;
  const char *use_topic = topic ? topic : _pub_topic;

  // The MADS wire header (src/agent.cpp in the main MADS repo): "MADS" +
  // version(1) + format(1) + compression(1) + flags(1) + 4-byte schema.
  // format=0 (Json), compression=0 (None) -- the only combination this
  // library supports send- and receive-side. A bare 2-part [topic][payload]
  // frame is always read by real MADS peers as snappy-compressed, so this
  // 3-part header form is the only way to interoperate as plain JSON.
  uint8_t header[12] = {'M', 'A', 'D', 'S', 1, 0, 0, 0, 0, 0, 0, 0};

  // One call, so the mechanism can put all three frames in a single
  // transport write where it can -- see ZmtpSession::send_frames3(). Under
  // NULL this is the same three sends it always was.
  bool sent = _pub_session.send_frames3(
      reinterpret_cast<const uint8_t *>(use_topic), strlen(use_topic), header,
      sizeof(header), reinterpret_cast<const uint8_t *>(json), json_len);

  if (!sent) {
    // Drop the socket so the next call goes through the reconnect path
    // rather than writing more frames into a half-dead connection (which
    // would also desynchronise the peer's frame parser mid-message).
    _pub_transport.close();
    _pub_assumed_up = false;
  }
  return sent;
}

bool Agent::publish(JsonDocument &payload, const char *topic) {
  payload["agent_id"] = _agent_id;
  payload["hostname"] = _hostname;
  payload["millis"] = millis();

  size_t len = serialize_envelope(payload);
  if (len == 0)
    return false;
  return publish(_publish_buf, len, topic);
}

bool Agent::publish(const uint8_t *blob, size_t blob_len, JsonDocument &meta,
                    const char *topic) {
  if (!blob && blob_len > 0)
    return false;

  meta["agent_id"] = _agent_id;
  meta["hostname"] = _hostname;
  meta["millis"] = millis();
  // Same default the desktop Agent's blob publish() carries in its meta
  // parameter; consumers (`mads echo`, plugin loaders) read this key to
  // decide how to interpret the bytes, falling back to "raw" themselves.
  if (meta["format"].isNull())
    meta["format"] = "raw";

  size_t meta_len = serialize_envelope(meta);
  if (meta_len == 0)
    return false;

  if (!ensure_pub_link())
    return false;
  const char *use_topic = topic ? topic : _pub_topic;

  // [topic][json meta][raw bytes] -- the legacy 3-part blob frame, which is
  // what the desktop Agent emits for a blob under the JSON wire format, and
  // deliberately header-less: see the overload's doc comment in the header.
  bool sent =
      _pub_session.send_frame(reinterpret_cast<const uint8_t *>(use_topic),
                              strlen(use_topic), true) &&
      _pub_session.send_frame(reinterpret_cast<const uint8_t *>(_publish_buf),
                              meta_len, true) &&
      _pub_session.send_frame(blob, blob_len, false);

  if (!sent)
    _pub_transport.close(); // same half-sent-message reasoning as above
  return sent;
}

size_t Agent::serialize_envelope(JsonDocument &doc) {
  size_t len = serializeJson(doc, _publish_buf, sizeof(_publish_buf));
  // serializeJson() truncates silently when the buffer is too small, and
  // only NUL-terminates when the text fit strictly within it -- so a result
  // filling the buffer exactly is either truncated or unterminated, and
  // either way must not be sent (or read back by last_publish_json()).
  if (len >= sizeof(_publish_buf))
    return 0;
  return len;
}

bool Agent::poll(char *topic_out, size_t topic_cap, uint8_t *payload_out,
                 size_t payload_cap, size_t &payload_len, uint32_t timeout_ms) {
  payload_len = 0;
  if (!_want_sub)
    return false;

  // Optional watchdog for a link that is still nominally connected but has
  // gone quiet -- catches half-open connections TCP hasn't noticed. Off by
  // default; see set_sub_silence_timeout() for why it isn't a good primary
  // liveness signal.
  if (_sub_silence_ms > 0 && _sub_transport.connected() &&
      (millis() - _last_sub_rx) > _sub_silence_ms)
    _sub_transport.close();

  if (!ensure_sub_link())
    return false;
  if (!_sub_transport.available())
    return false;

  uint8_t flags;
  uint64_t len;

  // Frame 0: topic.
  if (!_sub_session.recv_frame_header(flags, len, timeout_ms))
    return false;
  if (len >= topic_cap) {
    _sub_session.skip_frame_body(len, timeout_ms);
    return false;
  }
  if (!_sub_session.recv_frame_body(reinterpret_cast<uint8_t *>(topic_out),
                                    topic_cap, len, timeout_ms))
    return false;
  topic_out[len] = '\0';
  if (!(flags & ZmtpSession::FLAG_MORE))
    return false; // malformed: expected header+payload frames to follow

  // Frame 1: the 12-byte MADS header.
  if (!_sub_session.recv_frame_header(flags, len, timeout_ms))
    return false;
  uint8_t header[12];
  if (len != sizeof(header) ||
      !_sub_session.recv_frame_body(header, sizeof(header), len,
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
  if (!(flags & ZmtpSession::FLAG_MORE))
    return false;

  // Frame 2: payload.
  if (!_sub_session.recv_frame_header(flags, len, timeout_ms))
    return false;
  if (len > payload_cap) {
    _sub_session.skip_frame_body(len, timeout_ms);
    return false;
  }
  if (!_sub_session.recv_frame_body(payload_out, payload_cap, len,
                                    timeout_ms))
    return false;
  payload_len = static_cast<size_t>(len);
  _last_sub_rx = millis();
  return true;
}

} // namespace Mads
