#pragma once
#include "toml_scan.hpp"
#include "wifi_transport.hpp"
#include "z85.hpp"
#include "zmtp_session.hpp"
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
 * ZMTP 3.0 client (ZmtpSession) instead of the full libzmq/zmqpp stack the
 * desktop Mads::Agent depends on.
 *
 * Deliberately out of scope, matching this library's narrow purpose: CURVE
 * encryption, MsgPack, Snappy compression, dynamic re-subscription, and
 * settings persistence. Binary blobs can be published (see the
 * publish(const uint8_t *, size_t, JsonDocument &) overload) but never
 * received.
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
   * Publishes a binary blob: `blob_len` bytes sent verbatim, preceded by a
   * JSON metadata part, as `[topic][json meta][raw bytes]` -- exactly the
   * frame the desktop Agent's publish(const char *, size_t, meta, topic)
   * emits under the default (JSON) wire format. Note the absence of the
   * 12-byte MADS header the other two overloads send: the header-carrying
   * blob form ([topic][header(has_blob)][meta][bytes]) is only emitted by
   * the desktop Agent for MsgPack, and a real MADS peer tells a header-less
   * blob from a legacy compressed-JSON message by part count alone (3 vs 2).
   *
   * `meta` is mutated in place, like publish(JsonDocument&): the same
   * envelope fields (`agent_id`, `hostname`, `millis`) are merged in, and
   * `format` is set to "raw" if the caller left it unset -- consumers such
   * as `mads echo` read the blob's kind from that key. Only the metadata
   * passes through this class's internal serialization buffer; the blob
   * itself is written straight from the caller's memory, so its size is
   * bounded by the link, not by this library's RAM budget.
   */
  bool publish(const uint8_t *blob, size_t blob_len, JsonDocument &meta,
               const char *topic = nullptr);

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
  void set_reconnect_interval(uint32_t ms) {
    _reconnect_interval_ms = ms;
    reset_curve_backoff();
    reset_wifi_backoff();
  }
  uint32_t reconnect_interval() const { return _reconnect_interval_ms; }

#ifdef MADS_ENABLE_CURVE
  /**
   * Arms CURVE for every connection this agent opens. Call before begin().
   * The three arguments are the 40-character Z85 lines written by
   * `mads --keypair=<name>`: the client's own .pub and .key, and the
   * broker's .pub.
   *
   * Returns false if any of them fails to decode, in which case nothing is
   * armed and the agent stays on the NULL mechanism -- so a mistyped key
   * fails here, loudly and at once, instead of turning into a handshake
   * that mysteriously never completes.
   *
   * The keys are copied into this object, so the caller's strings need not
   * outlive the call; the copy is what the reconnect path re-uses.
   */
  bool set_crypto(const char *client_public_z85, const char *client_secret_z85,
                  const char *broker_public_z85) {
    // Decode into a temporary first: a half-armed agent -- valid client key,
    // mistyped broker key -- would be worse than a cleanly refused one.
    CurveKeys k{};
    if (!z85_decode(client_public_z85, k.client_public) ||
        !z85_decode(client_secret_z85, k.client_secret) ||
        !z85_decode(broker_public_z85, k.server_public))
      return false;
    _curve_keys = k;
    _curve_ready = true;
    reset_curve_backoff();
    return true;
  }

  /// True once set_crypto() has succeeded.
  bool crypto_enabled() const { return _curve_ready; }

  /// Why the last CURVE handshake failed. The only diagnostic a sketch gets,
  /// and worth printing: CurveError::rejected means this board's .pub is not
  /// in the broker's keys directory, or the broker was not restarted after
  /// it was added there.
  CurveError last_curve_error() const { return curve_last_error(); }

  /**
   * Current retry interval for a *rejected* handshake, in ms.
   *
   * A rejected handshake is deterministic -- it will not fix itself without
   * someone touching the broker -- and each attempt costs four X25519
   * scalar multiplications, measured at ~180 ms of blocking compute on the
   * board. So that case alone backs off exponentially from
   * reconnect_interval() to curve_backoff_max(), instead of burning that
   * every second forever. A failed TCP connect does *not* back off: that is
   * the "broker not up yet" case, it is cheap, and it self-heals.
   *
   * Exposed so a sketch can say why it has gone quiet -- a board that has
   * silently slowed to one attempt a minute should be able to report it.
   */
  /**
   * The PUB session's outgoing CURVE nonce counter.
   *
   * A completed handshake leaves this at 3 -- HELLO took 1 and INITIATE
   * took 2 -- after which every MESSAGE frame consumes one. Its value right
   * after a reconnect is the check DEVELOPER.md, and seeing
   * it back at 3 confirms the session state really was wiped and
   * renegotiated rather than carried across the reconnect.
   */
  uint64_t curve_nonce_out() const {
    return _pub_session.curve_state().nonce_out;
  }

  uint32_t curve_backoff() const { return _curve_backoff_ms; }
  uint32_t curve_backoff_max() const { return _curve_backoff_max_ms; }
  void set_curve_backoff_max(uint32_t ms) { _curve_backoff_max_ms = ms; }
#endif

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

  /**
   * How often the PUB link is torn down and re-established regardless of
   * how healthy it looks, in ms. Default 60000; 0 disables it.
   *
   * This exists because on this platform a dead PUB link is undetectable.
   * `WiFiClient::connected()` asks the ESP32 for the socket state, and after
   * a broker restart the ESP32 goes on reporting the socket as established
   * while `write()` keeps accepting bytes -- measured holding for over two
   * minutes, during which the board published 746 messages, reported every
   * one as successful, and delivered none. A PUB socket receives no reply
   * traffic, so there is nothing to time out on and no evidence of life to
   * wait for: periodically rebuilding the link is the only reliable defence.
   *
   * The cost is one handshake per interval -- negligible under NULL, and
   * about 180 ms under CURVE, so roughly 0.3% of a minute. Silent data loss
   * is much the worse failure, which is why this defaults to on.
   *
   * A PUB socket carries no unacknowledged state, so rebuilding it loses
   * nothing beyond messages already handed to a link that was not carrying
   * them anyway.
   */
  void set_pub_refresh_interval(uint32_t ms) { _pub_refresh_ms = ms; }
  uint32_t pub_refresh_interval() const { return _pub_refresh_ms; }

  /**
   * Reads and discards whatever the broker has sent down the PUB link,
   * returning how many bytes went. Normally there is something: a ZMTP XSUB
   * peer forwards subscription updates to its publishers, and this client
   * has no use for them.
   *
   * Draining is not housekeeping, it is what makes dead-link detection
   * possible at all. `WiFiClient::connected()` returns 1 immediately when
   * `available() > 0`, without ever asking the ESP32 -- so one unread byte
   * left sitting in the receive buffer makes the link look alive forever,
   * including long after the broker has gone. Emptying the buffer is what
   * forces connected() to go and ask.
   */
  size_t drain_pub();

  /**
   * How often the PUB link's liveness is actually probed, in ms.
   * Default 1000; 0 probes on every publish, as this library used to.
   *
   * `WiFiClient::connected()` is a round-trip to the ESP32 costing a
   * measured **9.6 ms** on this board -- roughly a third of a publish. It is
   * also, on its own, not trustworthy: see set_pub_refresh_interval() for
   * the broker-restart case it fails to notice. Paying that on every publish
   * therefore buys very little, and between probes a broken link is still
   * caught by a failed write and, ultimately, by the refresh timer.
   */
  void set_link_check_interval(uint32_t ms) { _link_check_ms = ms; }
  uint32_t link_check_interval() const { return _link_check_ms; }

  /**
   * Current interval between WiFi *association* attempts, in ms.
   *
   * Rejoining is rate-limited separately from broker reconnection, and backs
   * off from reconnect_interval() to wifi_backoff_max() while the join keeps
   * failing. Two reasons, both learned the hard way:
   *
   * Re-entering WiFi.begin() every second or two restarts an association
   * that is already in progress, and doing that repeatedly can leave the
   * ESP32 module unresponsive -- no scan results, no connection, and
   * (because uploading depends on the running sketch's USB stack) sometimes
   * not even reflashable without unplugging the board.
   *
   * And the publish and poll paths each used to call ensure_wifi()
   * independently, so a sketch doing both doubled the rate. They now share
   * one attempt clock.
   *
   * A join that succeeds resets this to reconnect_interval(). Unlike the
   * broker reconnect interval, backing off here costs nothing: WiFi
   * association is not something the sketch can hurry along.
   */
  uint32_t wifi_backoff() const { return _wifi_backoff_ms; }
  uint32_t wifi_backoff_max() const { return _wifi_backoff_max_ms; }
  void set_wifi_backoff_max(uint32_t ms) { _wifi_backoff_max_ms = ms; }

  /// The agent_id merged into published messages: the constructor-given
  /// value, or (once begin() has joined WiFi) the MAC-address fallback.
  const char *agent_id() const { return _agent_id; }
  /// The hostname merged into published messages: this board's local IP,
  /// resolved once begin() has joined WiFi.
  const char *hostname() const { return _hostname; }
  /// The exact JSON text sent by the most recent publish(JsonDocument&)
  /// call, or the metadata part of the most recent blob publish() -- for
  /// logging/diagnostics.
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
  /// Serializes `doc` into _publish_buf. Returns the byte count, or 0 if it
  /// did not fit (see the definition for why a full buffer counts as a
  /// failure rather than a snug fit).
  size_t serialize_envelope(JsonDocument &doc);

  WifiTransport _pub_transport;
  WifiTransport _sub_transport;
  ZmtpSession _pub_session{_pub_transport};
  ZmtpSession _sub_session{_sub_transport};
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

  // -------------------------------------------------------------------
  // CURVE state, declared here and stubbed in the #else so mads_agent.cpp
  // needs no #ifdef of its own -- the same seam pattern ZmtpSession uses.
  // Under NULL every hook below is an empty inline and every branch folds
  // away.
  // -------------------------------------------------------------------
#ifdef MADS_ENABLE_CURVE
  /// Arms both sessions from the decoded keys. Called on every link setup,
  /// because a session that has been reset() has also forgotten them.
  void arm_session(ZmtpSession &s) {
    if (_curve_ready)
      s.set_curve_keys(&_curve_keys);
  }
  /// Grows the retry interval, but only for the rejected case.
  void note_handshake_failure() {
    if (!_curve_ready || curve_last_error() != CurveError::rejected)
      return;
    const uint32_t doubled = _curve_backoff_ms * 2;
    _curve_backoff_ms = (doubled > _curve_backoff_max_ms || doubled < _curve_backoff_ms)
                            ? _curve_backoff_max_ms
                            : doubled;
  }
  void note_handshake_success() { reset_curve_backoff(); }
  void reset_curve_backoff() { _curve_backoff_ms = _reconnect_interval_ms; }
  uint32_t retry_interval() const { return _curve_backoff_ms; }

  CurveKeys _curve_keys{};
  bool _curve_ready = false;
  uint32_t _curve_backoff_ms = 1000;
  uint32_t _curve_backoff_max_ms = 60000;
#else
public:
  /// Always false in a build without CURVE compiled in. Present in both
  /// modes so a sketch can branch on it -- a status LED, a startup banner --
  /// without an #ifdef of its own. Stubbed here inside the existing #else
  /// rather than as a new guard block, which Sec 2's budget has no room for.
  static constexpr bool crypto_enabled() { return false; }

private:
  void arm_session(ZmtpSession &) {}
  void note_handshake_failure() {}
  void note_handshake_success() {}
  void reset_curve_backoff() {}
  uint32_t retry_interval() const { return _reconnect_interval_ms; }
#endif

  /// Shared by every ensure_wifi() caller, so the pub, sub and settings
  /// paths cannot each run their own association attempt.
  void reset_wifi_backoff() { _wifi_backoff_ms = _reconnect_interval_ms; }
  uint32_t _link_check_ms = 1000;
  uint32_t _last_link_check = 0;
  bool _pub_assumed_up = false;
  uint32_t _pub_refresh_ms = 60000;
  uint32_t _last_pub_connect = 0;
  uint32_t _wifi_backoff_ms = 1000;
  uint32_t _wifi_backoff_max_ms = 30000;
  uint32_t _last_wifi_attempt = 0;
  bool _wifi_attempted = false;

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
