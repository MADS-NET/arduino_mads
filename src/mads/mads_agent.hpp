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
  /// Optional: only needed if this agent also receives messages.
  bool connect_sub(uint32_t timeout_ms = 3000);

  /// Registers interest in `topic`. Requires a prior successful connect_sub().
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
  int timecode_fps() const { return _timecode_fps; }
  uint16_t frontend_port() const { return _frontend_port; }
  uint16_t backend_port() const { return _backend_port; }

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

private:
  bool fetch_settings(const char *agent_name, uint16_t settings_port,
                      uint32_t timeout_ms);

  WifiTransport _pub_transport;
  WifiTransport _sub_transport;
  const char *_broker_host = nullptr;
  const char *_pub_topic = nullptr;
  uint16_t _frontend_port = 9090;
  uint16_t _backend_port = 9091;
  int _timecode_fps = 25;
  bool _sub_connected = false;
  TomlScan _settings_scan;

  static constexpr size_t AGENT_ID_CAP = 32;  // fits "AA:BB:CC:DD:EE:FF" + room for a custom id
  static constexpr size_t HOSTNAME_CAP = 16;  // "255.255.255.255\0"
  static constexpr size_t PUBLISH_BUF_CAP = 256;
  char _agent_id[AGENT_ID_CAP] = {0};
  bool _agent_id_explicit = false;
  char _hostname[HOSTNAME_CAP] = {0};
  char _publish_buf[PUBLISH_BUF_CAP] = {0};
};

} // namespace Mads
