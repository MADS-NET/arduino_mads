#pragma once
#include "toml_scan.hpp"
#include "wifi_transport.hpp"
#include <ArduinoJson.h>
#include <cstddef>
#include <cstdint>

#ifndef MADS_LIB_VERSION
// Must match the target broker's major.minor (Mads::check_version() only
// compares up to the last '.'); override at build time if pointing at a
// different MADS release.
#define MADS_LIB_VERSION "v2.4.0"
#endif

namespace Mads {

/**
 * A minimal, first-class MADS agent for the Arduino UNO R4 WiFi: talks
 * directly to an unmodified mads-broker over WiFi, using a from-scratch
 * ZMTP 3.0 client (ZmtpCodec) instead of the full libzmq/zmqpp stack the
 * desktop Mads::Agent depends on.
 *
 * Deliberately out of scope, matching this library's narrow purpose: CURVE
 * encryption, MsgPack, Snappy compression, blob/binary payloads, dynamic
 * re-subscription, and settings persistence.
 *
 * publish(JsonDocument&) merges the caller's payload with the standard
 * MADS envelope fields every desktop agent's messages carry -- `agent_id`,
 * `hostname` -- plus `millis` in place of the desktop Agent's `timecode`/
 * `timestamp` (there is no RTC on this board, so a monotonic
 * milliseconds-since-boot counter stands in for wall-clock time). This is
 * why ArduinoJson is a real dependency of this class, not just a suggestion
 * for callers: merging fields into an arbitrary caller-built document
 * requires understanding its structure, not just forwarding opaque bytes.
 * The lower-level publish(const char*, size_t) overload -- plain wire
 * framing, no merge -- remains available beneath it.
 *
 * Usage shape: call begin() once from setup() (blocking, does the settings
 * REQ/REP exchange and opens the PUB connection); call publish() and,
 * if subscribed, poll() from loop() (poll() never blocks).
 *
 * Reconnection: both links self-heal. When a link is down, publish()/poll()
 * retry it at most once per reconnect_interval() (default 1s), rejoining
 * WiFi and re-fetching settings first if needed, and replaying SUB
 * subscriptions on a fresh SUB socket. This also covers "broker wasn't up
 * yet when the board booted": begin() may fail, but a loop() that keeps
 * calling publish() will connect as soon as the broker appears.
 *
 * The retry itself is NOT asynchronous -- Arduino's Client API has no
 * non-blocking connect, so a single attempt against an unreachable host
 * blocks loop() for however long WiFiClient::connect() takes to give up.
 * The per-interval rate limit bounds how often that happens, not how long
 * one attempt lasts.
 */
class Agent {
public:
  /**
   * @param agent_id Explicit agent identifier. If null/empty (the
   *  default), the agent_id merged into published messages falls back to
   *  this board's WiFi MAC address (colon-separated hex), resolved once
   *  begin() has joined WiFi.
   */
  explicit Agent(const char *agent_id = nullptr);

  /**
   * Joins WiFi (if not already connected), fetches settings from the
   * broker's REQ/REP port, and opens the PUB connection to the broker's
   * XSUB (frontend) port. Blocking; intended to be called once from
   * setup().
   *
   * @param broker_host The broker's IP/hostname -- NOT taken from the
   *  settings reply, which is why it must be supplied directly: the
   *  desktop Agent only reuses the *port* out of frontend_address/
   *  backend_address, substituting whatever host was used to reach the
   *  settings port (see Mads::Agent::query_broker in the main MADS repo).
   *  This class does the same -- broker_host is always what you dial.
   * @param settings_port The broker's settings REP port (mads.ini default: 9092).
   * @param agent_name Sent as part of the settings request; the broker
   *  does not require a matching config section to exist.
   * @param pub_topic Default topic used by publish() when none is given.
   */
  bool begin(const char *ssid, const char *pass, const char *broker_host,
             uint16_t settings_port, const char *agent_name,
             const char *pub_topic, uint32_t timeout_ms = 5000);

  /// Opens the SUB connection (this agent -> broker's XPUB/backend port).
  /// Optional: only needed if this agent also receives messages. Marks this
  /// agent as wanting a SUB link, so poll() will keep it alive from then on.
  bool connect_sub(uint32_t timeout_ms = 3000);

  /**
   * Registers interest in `topic`. The topic is remembered (up to
   * MAX_SUB_TOPICS) and automatically re-sent whenever the SUB link is
   * re-established -- ZMTP subscriptions live on the connection, so a
   * reconnected socket starts with none. Safe to call before
   * connect_sub(): the topic is stored and applied once the link opens.
   */
  bool subscribe(const char *topic);

  /// Publishes `json_len` bytes of uncompressed JSON text under `topic`
  /// (or this agent's default pub_topic if `topic` is null). Low-level:
  /// sends `json` verbatim, no envelope fields merged in.
  bool publish(const char *json, size_t json_len, const char *topic = nullptr);

  /**
   * Merges `agent_id`, `hostname` and `millis` into `payload` (mutating it
   * in place), serializes the result, and publishes it -- the standard,
   * recommended way to publish from this library. See the class doc for
   * why these particular fields and why ArduinoJson is required for this
   * overload.
   */
  bool publish(JsonDocument &payload, const char *topic = nullptr);

  /**
   * Non-blocking: if a message is waiting on the SUB connection, decodes it
   * into `topic_out`/`payload_out` and returns true; otherwise returns
   * false immediately. Malformed or non-JSON-uncompressed frames (e.g. the
   * legacy 2-part snappy form, or MsgPack) are dropped rather than
   * surfaced, matching the desktop Agent's "never crash on a bad frame"
   * policy -- callers just see no message that iteration.
   *
   * @param timeout_ms Per-frame read timeout once a message has started
   *  arriving (not a poll-wide timeout: a genuinely absent message returns
   *  immediately without waiting for this).
   */
  bool poll(char *topic_out, size_t topic_cap, uint8_t *payload_out,
            size_t payload_cap, size_t &payload_len, uint32_t timeout_ms = 200);

  bool connected() { return _pub_transport.connected(); }
  bool sub_connected() { return _sub_transport.connected(); }
  /// True once a settings reply has been successfully parsed. Worth
  /// checking from loop() when begin() failed (e.g. the broker wasn't up
  /// yet at boot): the reconnect path re-runs the settings exchange, so
  /// per-agent settings become available later without a restart.
  bool settings_ok() const { return _settings_ok; }
  int timecode_fps() const { return _timecode_fps; }
  uint16_t frontend_port() const { return _frontend_port; }
  uint16_t backend_port() const { return _backend_port; }

  /**
   * Minimum delay between reconnect attempts for a down link (default
   * 1000ms). publish()/poll() attempt at most one reconnect per interval,
   * so a persistently unreachable broker doesn't turn loop() into a busy
   * retry spin.
   */
  void set_reconnect_interval(uint32_t ms) { _reconnect_interval_ms = ms; }
  uint32_t reconnect_interval() const { return _reconnect_interval_ms; }

  /**
   * Optional SUB liveness watchdog: if more than `ms` elapse with no
   * message received on a SUB link that is still nominally connected,
   * treat it as dead and reconnect. Default 0 (disabled).
   *
   * Disabled by default on purpose: a SUB socket is passive, so "no data"
   * is indistinguishable from "subscribed topic is simply quiet", and a
   * too-eager timer would tear down healthy links on low-rate topics. Real
   * drops are already caught by the transport's connected() check, which
   * costs nothing and never false-positives. Enable this only when you
   * expect traffic at a known minimum rate (set `ms` to several times that
   * period), to also catch half-open connections where TCP never notices
   * the peer vanished.
   */
  void set_sub_silence_timeout(uint32_t ms) { _sub_silence_ms = ms; }
  uint32_t sub_silence_timeout() const { return _sub_silence_ms; }

  /// The agent_id merged into published messages: the constructor-given
  /// value, or (once begin() has joined WiFi) the MAC-address fallback.
  const char *agent_id() const { return _agent_id; }
  /// The hostname merged into published messages: this board's local IP,
  /// resolved once begin() has joined WiFi.
  const char *hostname() const { return _hostname; }
  /// The exact JSON text sent by the most recent publish(JsonDocument&)
  /// call -- for logging/diagnostics.
  const char *last_publish_json() const { return _publish_buf; }

  /**
   * Per-agent settings, read from the `[agent_name]` section of the same
   * settings reply fetched by begin() (e.g. `ai`/`di`/`delay` in a
   * `[uno_r4]` section) -- mirrors how the desktop Agent's subclasses read
   * their own settings via get_settings(), just restricted to flat
   * integers/integer-arrays given this library's RAM budget. Valid only
   * after a successful begin(); unknown keys fall back to `default_value`
   * (setting_int) or return 0 (setting_int_array).
   */
  int setting_int(const char *key, int default_value = 0) const {
    return _settings_scan.int_value(key, default_value);
  }
  size_t setting_int_array(const char *key, int *out, size_t max) const {
    return _settings_scan.int_array(key, out, max);
  }

public:
  static constexpr size_t MAX_SUB_TOPICS = 4;

private:
  bool fetch_settings(uint32_t timeout_ms);
  /// Joins WiFi if needed and waits for a DHCP-assigned IP, refreshing
  /// _hostname (and _agent_id on first resolution). False on timeout.
  bool ensure_wifi(uint32_t timeout_ms);
  /// Brings the PUB link up if it is down, rate-limited to one attempt per
  /// _reconnect_interval_ms. True if the link is usable on return.
  bool ensure_pub_link();
  /// Same for the SUB link; replays stored subscriptions on a fresh socket.
  bool ensure_sub_link();

  WifiTransport _pub_transport;
  WifiTransport _sub_transport;
  const char *_broker_host = nullptr;
  const char *_pub_topic = nullptr;
  // Retained so a reconnect can rejoin WiFi and re-run the settings
  // exchange without the sketch having to hand them over again.
  const char *_ssid = nullptr;
  const char *_pass = nullptr;
  const char *_agent_name = nullptr;
  uint16_t _settings_port = 9092;
  uint32_t _timeout_ms = 5000;
  uint16_t _frontend_port = 9090;
  uint16_t _backend_port = 9091;
  int _timecode_fps = 25;
  bool _settings_ok = false;
  bool _want_sub = false;
  TomlScan _settings_scan;

  uint32_t _reconnect_interval_ms = 1000;
  uint32_t _sub_silence_ms = 0;
  uint32_t _last_pub_attempt = 0;
  uint32_t _last_sub_attempt = 0;
  uint32_t _last_sub_rx = 0;
  bool _pub_attempted = false;
  bool _sub_attempted = false;

  static constexpr size_t AGENT_ID_CAP = 32;  // fits "AA:BB:CC:DD:EE:FF" + room for a custom id
  static constexpr size_t HOSTNAME_CAP = 16;  // "255.255.255.255\0"
  static constexpr size_t PUBLISH_BUF_CAP = 256;
  static constexpr size_t SUB_TOPIC_CAP = 24;
  char _agent_id[AGENT_ID_CAP] = {0};
  bool _agent_id_explicit = false;
  char _hostname[HOSTNAME_CAP] = {0};
  char _publish_buf[PUBLISH_BUF_CAP] = {0};
  char _sub_topics[MAX_SUB_TOPICS][SUB_TOPIC_CAP] = {};
  size_t _sub_topic_count = 0;
};

} // namespace Mads
