# MadsUnoAgent

Turn an **Arduino UNO R4 WiFi** into a first-class agent of the
[MADS](https://github.com/pbosetti/MADS) framework — publishing sensor data
straight to a MADS broker over WiFi, with no host PC in between.

The desktop `Mads::Agent` needs libzmq, zmqpp and libsodium: about 3 MB of
code and several threads, which will never fit a 32 KB microcontroller. This
library reimplements just the part of the ZMTP 3.0 wire protocol MADS
actually uses, in about 70 KB of flash.

```cpp
#include <MadsUnoAgent.h>

Mads::Agent agent;
JsonDocument doc;

void setup() {
  agent.begin("my-ssid", "my-password", "192.168.1.10", 9092, "uno_r4", "sensors");
}

void loop() {
  doc.clear();
  doc["a0"] = analogRead(A0);
  agent.publish(doc);            // -> topic "sensors" on the broker
  delay(200);
}
```

**Optionally encrypted.** Point it at a `mads broker --crypto` and it speaks
CurveZMQ — the same X25519 + Salsa20/Poly1305 handshake libzmq uses. See
[Encrypted connections](#encrypted-connections) below. Encryption is off
unless you switch it on at build time, and costs nothing when off.

Internals, measurements and maintenance notes live in
[DEVELOPER.md](DEVELOPER.md).

## Contents

- [Install](#install)
- [Publishing](#publishing)
- [Receiving](#receiving)
- [Per-agent settings](#per-agent-settings)
- [Encrypted connections](#encrypted-connections)
- [How fast can it publish?](#how-fast-can-it-publish)
- [Status LED](#status-led)
- [Troubleshooting](#troubleshooting)
- [What has been tested](#what-has-been-tested)

---

## Install

Not in the Arduino Library Manager index yet, so install by hand.

**Arduino IDE** — either *Sketch → Include Library → Add .ZIP Library…* on a
zip of this repository, or copy the repository into your sketchbook's
`libraries/` folder as `MadsUnoAgent`:

| | |
|---|---|
| macOS | `~/Documents/Arduino/libraries/MadsUnoAgent` |
| Linux | `~/Arduino/libraries/MadsUnoAgent` |
| Windows | `Documents\Arduino\libraries\MadsUnoAgent` |

Restart the IDE, then install **ArduinoJson** (by Benoit Blanchon) from
Library Manager. A manual copy does not pull dependencies in automatically.

**arduino-cli** — point `--library` straight at a working copy:

```sh
arduino-cli core install arduino:renesas_uno
arduino-cli lib install ArduinoJson

arduino-cli compile --fqbn arduino:renesas_uno:unor4wifi \
  --library /path/to/arduino_mads examples/uno_r4_sensor
```

You do not need `#include <ArduinoJson.h>` in your sketch —
`MadsUnoAgent.h` pulls it in.

## Publishing

`publish(JsonDocument&)` adds the standard MADS envelope fields for you —
`agent_id`, `hostname` and `millis` — so your payload arrives looking like
any other MADS agent's:

```json
{"a0":247,"agent_id":"A0:D2:36:45:3A:B4","hostname":"192.168.1.42","millis":12052}
```

`agent_id` defaults to the WiFi MAC; pass your own to the constructor
(`Mads::Agent agent("kiln_1")`) if you prefer. There is no RTC on this board,
so `millis` stands in for the desktop agent's `timecode`/`timestamp`.

**Binary blobs** go out as `[topic][json meta][raw bytes]`, streamed straight
from your buffer, so blob size is limited by the link and not by the
library's RAM:

```cpp
uint8_t frame[1024];
JsonDocument meta;
meta["format"] = "adc_u8";
agent.publish(frame, sizeof(frame), meta, "blobs");
```

Payloads are JSON, uncompressed. MsgPack and Snappy are not supported.

## Receiving

Subscribing is optional. Call `connect_sub()` once, `subscribe()` per topic,
then poll from `loop()` — it never blocks for long:

```cpp
agent.subscribe("commands");
agent.connect_sub();
...
char topic[32];
uint8_t payload[256];
size_t len;
if (agent.poll(topic, sizeof(topic), payload, sizeof(payload), len, 20)) {
  // got a message
}
```

> **Note.** `subscribe()` returns `false` if the SUB link is not up yet. The
> topic *is* remembered and sent as soon as the link opens, so this is not an
> error — don't treat it as one.

There is a second gotcha worth knowing: after subscribing, the broker needs a
moment before it starts forwarding to you (ZMQ's "slow joiner"). Anything
published in that window is dropped, not queued. Measured at roughly 1.6–1.8 s
against a local broker, so don't publish once and expect it straight back.

Receiving blobs is not supported; `poll()` handles JSON messages only.

## Per-agent settings

The broker serves your `mads.ini`, and the board reads its own section — so
pin lists and delays live in configuration rather than in code:

```ini
[uno_r4]
ai = [0, 2, 4]
delay = 100
```

```cpp
int period = agent.setting_int("delay", 200);        // 200 if unset
int pins[8];
size_t n = agent.setting_int_array("ai", pins, 8);
```

`settings_ok()` tells you whether these have arrived yet. See
`examples/uno_r4_sensor`, which is driven entirely this way.

## Encrypted connections

Against a `mads broker --crypto`, the board can speak CurveZMQ. All three
connections are encrypted, the settings fetch included — there is no
unencrypted bootstrap.

### 1. Generate a key pair, on your PC

```sh
mads --keypair=uno_r4          # writes uno_r4.key (secret) and uno_r4.pub
```

Each file is a single 40-character line.

### 2. Tell the broker about the board

Copy `uno_r4.pub` into the broker's keys directory (`$(mads -p)/etc` by
default), then **restart the broker**. It reads `*.pub` only at startup, and
a broker that missed the restart rejects the board exactly as if the key were
unknown — this is the single most common setup mistake.

While you are there, set `auth_verbose = true` in `mads.ini`'s `[broker]`
section. The broker then logs `granted` or `DENIED` for every attempt, which
is by far the quickest way to see what is wrong.

### 3. Put the keys in your sketch

Copy `examples/crypto_pub/arduino_secrets.h.example` to `arduino_secrets.h`
and paste in the three 40-character lines: your `uno_r4.pub`, your
`uno_r4.key`, and the broker's `broker.pub`.

```cpp
if (!agent.set_crypto(SECRET_CURVE_CLIENT_PUBLIC,
                      SECRET_CURVE_CLIENT_SECRET,
                      SECRET_CURVE_BROKER_PUBLIC)) {
  Serial.println("a key is not valid Z85 -- check for stray spaces or quotes");
  while (true) delay(1000);
}
agent.begin(...);              // as usual, after set_crypto()
```

### 4. Build with encryption enabled

A `#define` in your sketch cannot reach the library, so it has to come from
the build:

```sh
arduino-cli compile --fqbn arduino:renesas_uno:unor4wifi \
  --build-property "build.extra_flags=-DMADS_ENABLE_CURVE" \
  --library /path/to/arduino_mads examples/crypto_pub
```

In the Arduino IDE there is no supported way to pass this, so use
arduino-cli for encrypted builds. (`build_opt.h` does **not** work on this
board's core — see [DEVELOPER.md](DEVELOPER.md).)

`examples/crypto_pub` refuses to run if the flag did not take, rather than
connecting in clear.

### What it costs

| | flash | RAM |
|---|---|---|
| without CURVE | ~70 KB (27%) | ~8.8 KB (27%) |
| with CURVE | ~89 KB (34%) | ~10.7 KB (33%) |

Connecting takes about **180 ms** of extra computation for the handshake
(four X25519 multiplications at ~45 ms each). After that, encryption costs
microseconds per message — see below.

### Two things to know about the keys

**One build is one identity.** The key pair is compiled into the binary, so
flashing the same `arduino_secrets.h` to five boards makes them
indistinguishable to the broker, which allow-lists by public key. Revoking
one revokes all five. If you need per-board identity, generate `uno_r4_01`,
`uno_r4_02`, … and build once per board. A shared fleet identity is a
perfectly reasonable choice — it just should be a choice.

**The secret key is in the binary, in the clear.** `arduino_secrets.h` is
gitignored, but the compiled `.bin` is not protected and the UNO R4's
bootloader is open, so anyone holding the board can read the key off it.
CURVE protects you against someone on the network, not against someone
holding the hardware.

## How fast can it publish?

Sustained **~29 messages/second** with encryption on, measured on hardware.

The interesting part is where the time goes, because it is not where people
expect:

| | |
|---|---|
| building the JSON | 62 µs |
| encrypting it | microseconds |
| **sending it** | **~35 ms** |

**Encryption is not the bottleneck — the WiFi module is.** Every write to the
network is an SPI round-trip to the on-board ESP32 costing about 4 ms, plus
about 30 ms of fixed overhead per publish. The library already packs a whole
publish into a single write for you; that alone took it from 18 to 29
messages/second.

Practical consequences:

* **Publishing blocks `loop()` for ~35 ms.** Budget for it.
* **Don't use `delay()` to pace publishing.** Schedule on `millis()` instead,
  or you pay the delay *and* the publish. `examples/crypto_pub` shows the
  pattern.
* **`Serial.println()` is not free** — about 8 ms for a typical line at
  115200. Printing every message costs you a quarter of your throughput.
* Fewer, larger messages beat many small ones. The cost is per *publish*,
  barely per byte.

Without encryption the numbers are similar: the network dominates either way.

## Status LED

`examples/crypto_pub` drives the built-in LED so you can read the connection
state from across the room. Each pattern repeats every 2 seconds:

| pattern | meaning |
|---|---|
| `#.......` one brief blink | joining WiFi |
| `#.#.....` two blinks | **the configured WiFi network is not on the air** |
| `########` solid | WiFi up, broker not joined |
| `####....` one long pulse | connected, **not** encrypted |
| `##.##...` two pulses | connected and **encrypted** |
| `#.#.#.#.` fast flutter | broker refused the key — see Troubleshooting |
| dark | no power, or the sketch is not running |

Two deliberate choices. "Not connected" blinks rather than staying dark, so
**dark means the board is not running** — the most useful thing one lamp can
tell you. And encrypted versus not differ by *counting* pulses rather than by
brightness or duty cycle, because that is the one distinction where
misreading it matters.

## Troubleshooting

| symptom | likely cause |
|---|---|
| `begin()` fails, LED shows two blinks | the WiFi network is not being broadcast. Phone hotspots sleep when a laptop is attached — open the Personal Hotspot screen to wake it |
| `begin()` fails, WiFi is up, `last_curve_error()` is `none` | the board reached WiFi but not the broker. Check the IP, and check the network does not isolate clients — **guest and hotel WiFi usually does**, which blocks the board from reaching your PC entirely |
| `CurveError::rejected`, LED fluttering | the broker does not know this key. Copy `uno_r4.pub` into its keys directory and **restart the broker** |
| `CurveError::disconnected` | the public and secret keys are not a pair — re-copy both lines |
| `CurveError::greeting` | the broker is not running with `--crypto` |
| `CurveError::mac` | wrong `broker.pub` |
| `set_crypto()` returns false | a key is not valid Z85 — check for stray spaces, quotes or a missing character |
| link stops recovering after a while | see below |
| data arrives (`mads echo` sees it) but the board is absent from `mads top` | expected — this library publishes data but does not send the `agent_event` announcement that `mads top` builds its list from |

`agent.last_curve_error()` is the diagnostic; print it when `begin()` fails.
`examples/crypto_pub` prints a plain-language explanation for each value.

**A note on reconnect behaviour.** If the broker refuses the key, retrying is
pointless until a human fixes it, so the interval backs off exponentially to
one attempt a minute (`curve_backoff()` reports it). Ordinary "broker not up
yet" failures are cheap and keep retrying at the normal interval.

**If the board stops responding entirely** — no serial output, and uploads
failing — unplug and replug it. Repeatedly re-entering `WiFi.begin()` (as
happens if a sketch retries a failing connection every second or two) can
leave the WiFi module unresponsive, and the reset button is not always enough
because uploading depends on the running sketch. Back off to about ten
seconds between connection attempts and it does not happen.

## What has been tested

Verified end to end on real hardware — an UNO R4 WiFi against an unmodified
`mads broker` built on full libzmq/zmqpp:

* settings fetch, including per-agent section parsing;
* publishing, decoded correctly by `mads echo`;
* reconnection, by stopping and restarting the broker under a running board;
* **encrypted** operation against `mads broker --crypto`: the broker logs
  `granted` for the board's connections, and 562 messages were published in
  164 s with one failure (the one before WiFi came up);
* the hardware random number generator, across power cycles.

Verified against a real broker, but from a desktop build rather than the
board: the SUB/`poll()` path, subscription replay after reconnect, and blob
publishing (including the >255-byte large-frame path).

Not yet exercised on hardware: blob publishing from the board, and the
optional SUB silence watchdog.

---

# License

MIT, see [LICENSE](LICENSE) for details.

# Author

Paolo Bosetti, University of Trento, Italy
