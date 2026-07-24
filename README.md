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
- JSON payloads only, uncompressed (`format=Json`, `compression=None` in the MADS wire header) --
  no MsgPack, no Snappy compression, no CURVE encryption. Callers build/parse the JSON text
  themselves (with ArduinoJson or otherwise); this library only handles framing.

The ZMTP handshake is deliberately pinned to protocol revision 3.0 (not the modern default 3.1):
this makes the broker's connection-local encoder use the simple, single-byte-prefixed
SUBSCRIBE/CANCEL frame instead of ZMTP 3.1's command-based one, and avoids needing to implement
PING/PONG heartbeats at all (MADS never enables ZMQ_HEARTBEAT_IVL).

See `examples/minimal_pub` for a PUB-only sensor agent, `examples/pub_sub` for one that also
receives, and `examples/uno_r4_sensor` for one driven entirely by its own `mads.ini` section
(pin lists and loop delay read from settings, not hardcoded).

## Status

Verified end-to-end on real hardware (Arduino UNO R4 WiFi) against an unmodified, real
`mads-broker` and a real desktop `mads-feedback` subscriber (both built on full libzmq/zmqpp):
settings REQ/REP (including per-agent `[uno_r4]` section parsing) and PUB messaging both work,
with published JSON correctly decoded on the desktop side.

Measured footprint for `examples/uno_r4_sensor` (`arduino-cli compile --fqbn
arduino:renesas_uno:unor4wifi`): 63,660 bytes flash (24% of 262,144) and 8,504 bytes of global
RAM (25% of 32,768), leaving 24,264 bytes free -- comfortably under budget; the WiFiS3 framework's
own footprint turned out smaller than initially estimated.

Not yet exercised on hardware: the SUB/poll() path (`examples/pub_sub`) and CURVE-enabled brokers
(out of scope by design -- see above).
