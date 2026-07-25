# MadsUnoAgent

Minimal, from-scratch ZMTP 3.0 client for the [MADS](https://github.com/pbosetti/MADS) agent
framework, targeting the Arduino UNO R4 WiFi.

The full `Mads::Agent` C++ class depends on libzmq/zmqpp/libsodium (~3MB of static code, several
background threads, C++20) and does not fit a 32KB-RAM microcontroller. This library instead
reimplements just enough of the ZMTP 3.0 wire protocol to act as a first-class MADS agent
directly over WiFi, with no host-PC bridge involved:

- One-shot, blocking REQ/REP settings retrieval against the broker's settings port (done once in
  `setup()`), extracting `frontend_address`/`backend_address`/`timecode_fps` from the `[agents]`
  section of the raw settings reply via a tiny streaming scanner (no toml++, no buffering the
  whole reply in RAM).
- Per-agent settings: the same scan also captures every `key = value` line from the agent's own
  section (e.g. `[uno_r4]`), so a sketch can read its own config -- pin lists, loop delays, etc. --
  via `Agent::setting_int()`/`Agent::setting_int_array()` instead of hardcoding it. See this
  repo's own `mads.ini` (`[uno_r4]`: `ai`, `di`, `delay`) and `examples/uno_r4_sensor`.
- PUB messaging against the broker's XSUB (frontend) port.
- Optional SUB messaging (with topic subscriptions) against the broker's XPUB (backend) port,
  polled non-blockingly from `loop()`.
- Self-healing links: a failed `publish()` (or a dropped SUB socket) puts that link into a
  reconnecting state, retried at most once per `set_reconnect_interval()` (default 1s) so a dead
  broker can't turn `loop()` into a busy spin. Reconnecting rejoins WiFi if needed, re-fetches
  settings, and replays SUB subscriptions -- ZMTP subscriptions are per-connection, so a fresh
  socket would otherwise go silent. The same path covers "the board booted before the broker
  existed": `begin()` may fail, but a `loop()` that keeps publishing connects once the broker
  appears (watch `settings_ok()` to know when per-agent settings finally arrived).
  Caveat: Arduino's `Client` API has no non-blocking connect, so one attempt against an
  unreachable host still blocks `loop()` for however long `WiFiClient::connect()` takes to give
  up; the interval bounds how *often* that happens, not how long an attempt lasts.
  For SUB, the primary liveness signal is the transport's `connected()` -- definitive and never a
  false positive. `set_sub_silence_timeout()` adds an optional "no data for N ms means dead"
  watchdog for half-open connections, but is **off by default on purpose**: a SUB socket is
  passive, so silence is indistinguishable from a genuinely quiet topic, and an eager timer would
  tear down healthy links on low-rate topics. Enable it only when you expect traffic at a known
  minimum rate.
- JSON payloads only, uncompressed (`format=Json`, `compression=None` in the MADS wire header) --
  no MsgPack, no Snappy compression, no CURVE encryption.
- Standard MADS envelope fields: `Agent::publish(JsonDocument&)` merges `agent_id`, `hostname` and
  `millis` into the caller's payload before sending -- the same shape every desktop MADS agent's
  messages carry (`agent_id`/`hostname`/`timecode`/`timestamp`), with `millis` standing in for
  `timecode`/`timestamp` since this board has no RTC. `agent_id` defaults to the WiFi MAC address
  (override via `Agent(const char *agent_id)`); `hostname` is the board's local IP. This is why
  ArduinoJson is a real dependency of this library (`library.properties`), not just a suggestion
  for callers -- merging fields into an arbitrary caller-built document requires understanding its
  structure. It's fully portable, plain C++ with no Arduino-specific requirement, so it needs no
  `#ifdef`/conditional to also compile in desktop unit tests, just the right include path. The
  lower-level `publish(const char*, size_t)` (no merge, sends bytes verbatim) remains available.
  Sketches don't need their own `#include <ArduinoJson.h>` -- `#include <MadsUnoAgent.h>` already
  pulls it in transitively (`MadsUnoAgent.h` -> `mads/mads_agent.hpp` -> `<ArduinoJson.h>`), so
  `JsonDocument`/`JsonArray`/`serializeJson` etc. are available straight away; see any example.

The library depends on the [ArduinoJSON](https://arduinojson.org) library by Benoit Blanchon.

The ZMTP handshake is deliberately pinned to protocol revision 3.0 (not the modern default 3.1):
this makes the broker's connection-local encoder use the simple, single-byte-prefixed
SUBSCRIBE/CANCEL frame instead of ZMTP 3.1's command-based one, and avoids needing to implement
PING/PONG heartbeats at all (MADS never enables ZMQ_HEARTBEAT_IVL).

See `examples/minimal_pub` for a PUB-only sensor agent, `examples/pub_sub` for one that also
receives, and `examples/uno_r4_sensor` for one driven entirely by its own `mads.ini` section
(pin lists and loop delay read from settings, not hardcoded).

## Install

Not yet published in the official Arduino Library Manager index, so install manually.

**Arduino IDE** -- either:
- Sketch -> Include Library -> Add .ZIP Library..., pointing at a zipped copy of this repository, or
- clone/copy this repository directly into your sketchbook's `libraries/` folder, naming the
  folder `MadsUnoAgent`:
  - macOS: `~/Documents/Arduino/libraries/MadsUnoAgent`
  - Linux: `~/Arduino/libraries/MadsUnoAgent`
  - Windows: `Documents\Arduino\libraries\MadsUnoAgent`

Then restart the IDE so it re-scans installed libraries, and install the one real dependency,
**ArduinoJson** (by Benoit Blanchon), via Library Manager -- a manual copy doesn't auto-resolve
`library.properties`' `depends` the way installing through Library Manager itself would.

**arduino-cli** -- either install it the same way (clone into the path reported by
`arduino-cli config dump`'s `directories.user`, default as above, then `arduino-cli lib install
ArduinoJson`), or skip installing entirely and point `--library` straight at a working copy, as
this project's own development/testing did throughout:

```
arduino-cli lib install ArduinoJson
arduino-cli compile --fqbn arduino:renesas_uno:unor4wifi \
  --library /path/to/arduino_mads \
  examples/uno_r4_sensor
```

Either way, also make sure the `arduino:renesas_uno` board core is installed (`arduino-cli core
install arduino:renesas_uno`, or via Boards Manager in the IDE).

## Status

Verified end-to-end on real hardware (Arduino UNO R4 WiFi) against an unmodified, real
`mads broker` and a real desktop `mads feedback` subscriber (both built on full libzmq/zmqpp):
settings REQ/REP (including per-agent `[uno_r4]` section parsing), PUB messaging, and the
ArduinoJson-based standard envelope (`agent_id`/`hostname`/`millis`) all work, with published JSON
correctly decoded on the desktop side. PUB reconnection was verified by stopping and restarting
the broker under a running board: it recovers on its own, with no reset.

Measured footprint for `examples/uno_r4_sensor` with ArduinoJson and reconnect support
(`arduino-cli compile --fqbn arduino:renesas_uno:unor4wifi`): ~70KB flash (26% of 262,144) and
~8.8KB of global RAM (26% of 32,768), leaving ~24KB free -- comfortably under budget; the WiFiS3
framework's own footprint turned out smaller than initially estimated.

Fixed timing issue: `WL_CONNECTED` (WiFi association) can fire before DHCP has actually assigned
an IP. An earlier version relied on `fetch_settings()`'s network round-trips to incidentally give
DHCP enough time before reading `WiFi.localIP()`, which worked once during bring-up but then
failed intermittently on reboot (`hostname` came back `"0.0.0.0"`, settings never fetched).
`begin()` now waits explicitly, in a bounded loop, for a non-zero `WiFi.localIP()` right after
`WL_CONNECTED` before doing anything else network-dependent.

Not yet exercised on hardware: the SUB/poll() path (`examples/pub_sub`) -- including its
reconnect/subscription-replay branch and the optional silence watchdog -- and CURVE-enabled
brokers (out of scope by design -- see above).

---

# License

MIT, see [LICENSE](LICENSE) for details.

# Author

Paolo Bosetti, University of Trento, Italy,