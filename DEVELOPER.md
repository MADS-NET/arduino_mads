# Developer notes

Internals, measurements and hard-won gotchas for anyone changing this library
— human or agent. Nothing here is needed to *use* it; see [README.md](README.md)
for that.

Related documents:

| file | what it is |
|---|---|
| [CURVE.md](CURVE.md) | the original feasibility study for CURVE, kept as the reasoning record |
| [CURVE_PLAN.md](CURVE_PLAN.md) | the implementation plan, with corrections applied where reality disagreed |
| [CURVE_HANDOFF.md](CURVE_HANDOFF.md) | phase-by-phase status and what was measured when |

---

## Architecture

```
Agent  (mads_agent.*)        settings fetch, publish/poll, reconnect policy
  └── ZmtpSession (zmtp_session.*)   ZMTP 3.0 framing + mechanism seam
        ├── NULL      inline, no state
        └── CURVE     curve.*  (handshake + MESSAGE framing)
              ├── crypto/nacl_box.*   secretbox, box_beforenm
              ├── crypto/salsa20.*    Salsa20 / HSalsa20 / XSalsa20
              ├── crypto/monocypher*  X25519, Poly1305
              ├── entropy_*.cpp       SCE TRNG (board) / urandom (desktop)
              └── z85.*               key decoding
  └── Transport (transport.hpp)  WifiTransport on board, POSIX socket in tests
```

### The mechanism seam

The requirement was that a build *without* CURVE be unchanged. That means the
**build output** is unchanged, not the source — reading it the other way
produces two interleaved protocol implementations in one file.

So there is exactly one seam. Every CURVE-specific member is declared in one
guarded block in `zmtp_session.hpp` and **stubbed in its `#else`**:

```cpp
#ifdef MADS_ENABLE_CURVE
  bool curve_active() const { return _curve_keys != nullptr; }
  bool curve_send(...);                 // defined in curve.cpp
#else
  static constexpr bool curve_active() { return false; }
  bool curve_send(...) { return false; }
#endif
```

The rest of the library then branches on plain `if (curve_active())` with no
`#ifdef` of its own. Under NULL that is a `constexpr false`, so the branch
folds away and the stubs are never emitted. `Agent` uses the same pattern —
which is why `Agent::crypto_enabled()` exists in both modes and
`set_crypto()` is defined inline in the header (out of line it would have
needed another guard block).

**Guard budget: 12, currently 12 used.** This is a design tripwire, not
bureaucracy: needing a thirteenth means the seam has drifted and the fix is
to move it back, not to raise the number.

```sh
grep -rn "^#ifdef MADS_ENABLE_CURVE\|^#if defined(MADS_ENABLE_CURVE)" src/ | wc -l
```

---

## Building and testing

### Desktop test suite

`src/mads/*.cpp` compiles unmodified against a POSIX-socket stand-in for
`WiFiS3.h`, so the real production sources run under ASan/UBSan without a
board.

```sh
cd test/desktop
export ARDUINOJSON_DIR=~/Documents/Arduino/libraries/ArduinoJson/src

make test                                   # NULL build
MADS_ENABLE_CURVE=1 make test               # CURVE build
```

Live tests skip cleanly unless pointed at a broker:

```sh
MADS_ENABLE_CURVE=1 \
MADS_BROKER_HOST=127.0.0.1 \
MADS_CURVE_KEYS_DIR=/path/to/keys \
MADS_NULL_BROKER_PORT=9090 \
  make test
```

| binary | needs a broker | what it covers |
|---|---|---|
| `test_toml_scan` | no | settings-reply scanner |
| `test_crypto_vectors` | no | RFC/NaCl vectors for every primitive |
| `test_curve_message` | no | MESSAGE framing, tamper/replay, Z85, write counts |
| `test_curve_golden` | no | pinned HELLO/INITIATE bytes |
| `test_entropy` | no | entropy backends, determinism of the test hook |
| `test_zmtp_null` | yes | NULL path end to end |
| `test_curve_handshake` | yes | handshake on all three socket types, error codes |
| `test_curve_agent` | yes | `set_crypto()`, backoff, Agent-level publish |

### The mock broker

`test/desktop/mock_broker.h` is a scripted CurveZMQ *server*: it seals a real
WELCOME and READY the client must open, and encrypts/decrypts MESSAGE frames
with the **opposite** directional nonce prefix. That last detail is the point
— a client round-tripped only against itself would pass even if both
directions shared a prefix, which is a real interoperability *and*
cryptographic bug.

### Golden vectors

`test_curve_golden` pins the exact HELLO and INITIATE bytes. Regenerate with:

```sh
MADS_CURVE_GOLDEN_GENERATE=1 ./build/test_curve_golden   # paste into curve_golden.inc
```

Determinism is over the **sequence** of `entropy_fill()` calls, not wall
time. Reordering or resizing those draws changes the goldens and that is
expected — say so in the commit. Bytes changing *without* the draw sequence
changing is a real protocol change and needs justifying.

A golden must only ever be recorded from a build already verified against a
real `mads broker --crypto`; one captured from an unverified run just
freezes a bug.

### Footprint proof

```sh
test/footprint_check.sh
```

Builds every example both ways and greps the linked ELF for
crypto/monocypher/salsa/poly1305/secretbox/curve/z85 symbols. **That symbol
count, not a byte count, is the property that matters** — a byte count goes
stale the moment anything unrelated moves. It also fails if the *enabled*
build has no crypto symbols, which catches a `--build-property` that silently
did not take.

### Stack usage

```sh
cd test/desktop
make stackreport        # host, -O0, for call-graph structure
make stackreport-arm    # the board's real toolchain and flags -- believe this one
python3 stackreport.py build/stackreport-arm curve_handshake   # one entry point
```

`stackreport.py` reads `-fstack-usage` output and walks the call graph from
`objdump -dr`. Four things it must keep doing, each of which was silently
wrong at some point:

* include `.c` sources — Monocypher is C and holds the deepest frames;
* read **relocations**, not just disassembly — in an unlinked object under
  `-ffunction-sections` every cross-function call is a placeholder pointing
  at the caller, so disassembly alone yields a graph of self-edges;
* reduce both `.su` signatures and demangled symbols to a qualified name —
  they never match verbatim, so every C++ frame looked like a leaf;
* accept clang's `.su` dialect (`file:line:mangled`) as well as GCC's
  (`file:line:col:signature`), or a macOS host silently reports zero
  functions.

---

## Measurements

All on an UNO R4 WiFi (RA4M1 @ 48 MHz), `arm-none-eabi-gcc` 7-2017q4 `-Os`,
core `arduino:renesas_uno@1.6.0`.

### Footprint

| build | flash | RAM |
|---|---|---|
| `crypto_pub`, CURVE off | 70264 | 8756 |
| `crypto_pub`, CURVE on | 89016 | 10708 |
| **CURVE costs** | **+18.3 KB** | **+1952 B** |

The three CURVE-free examples stay at 68952 / 70024 / 70144 flash. The plan
originally estimated +10–13 KB flash and +~300 B RAM; both were low. RAM is
794 B of `.bss` in `curve.cpp` plus ~336 B per `ZmtpSession`, of which
`SecretboxOpen` alone is 256 (a Salsa20 keystream block, a Poly1305 context,
and a 32-byte block-0 cache). It is per-session rather than static because a
session can sit mid-frame between calls and the Agent has two.

### Stack

| chain | own frame | full chain |
|---|---|---|
| `curve_handshake` | 104 B | 968 B |
| `curve_send` | 88 B | 760 B |
| `curve_recv_header` | 120 B | 560 B |
| `box_beforenm` (one X25519) | — | 864 B |

`BSP_CFG_STACK_MAIN_BYTES = 0x400` is a **guaranteed floor, not a ceiling**.
In `fsp.ld` the heap grows up from `__HeapBase` and the stack grows down from
`__StackTop`; nothing faults on crossing `__StackLimit`. Measured on a linked
`pub_sub`: 20436 bytes between them, and the crypto peaks at 1612–1668 B —
about 8%. The stack *does* cross the 1 KB reservation routinely and silently.

The real risk is therefore a **stack/heap collision, not a stack overflow**,
and it is a whole-sketch property: ArduinoJson v7 heap-allocates every
`JsonDocument`.

### Publish latency

This is the number that surprises people, so it is worth stating plainly:
**crypto is not the bottleneck; the number of `Transport::write()` calls is.**

| stage | cost |
|---|---|
| JSON build | 62 µs |
| Salsa20/Poly1305 for a publish | microseconds |
| **one `write()`** | **~4.2 ms** |
| **fixed, per publish** | **~30.6 ms** |
| `Serial.println` of one ~85-char line | 8.2 ms |

On this board a `write()` is an SPI round-trip to the ESP32-S3. Solving
`cost = fixed + n × per_write` from two measured points (6 writes → 55.8 ms,
1 write → 34.8 ms) gives the table above.

| version | writes per publish | `publish()` | sustained |
|---|---|---|---|
| one frame at a time | 6 | 55.8 ms | 17.9 Hz |
| header+body coalesced | 3 | — | — |
| all three frames batched | **1** | **34.8 ms** | **28.7 Hz** |

`send_frames3()` encrypts topic, MADS header and payload into one buffer and
issues a single write, falling back to three separate sends — without
consuming a nonce — if they would not fit.

**The remaining ~30.6 ms is not write count.** The likely candidate is
`ensure_pub_link()` calling `Transport::connected()` on every publish, itself
an ESP32 round-trip. Removing it would trade latency against noticing a dead
link later, so it is a reliability decision rather than a free win, and has
deliberately not been made.

Blob chunking follows the same logic: the plan suggested 64-byte chunks,
which predates knowing what a write costs. At 64 bytes a 16 KB blob is 256
writes ≈ 2.4 s. The chunk is a fixed slice of the existing static scratch, so
enlarging it to 256 does not make RAM scale with blob size — the property the
acceptance criterion actually protects.

---

## Hardware gotchas

Each of these cost real debugging time.

**`build_opt.h` cannot work on this core.** `renesas_uno@1.6.0`'s
`platform.txt` never references `{build.opt.path}`, so nothing reads the
file. Verified on arduino-cli 1.0.2 and 1.2.2. Use
`--build-property "build.extra_flags=-DMADS_ENABLE_CURVE"`, which the core
substitutes into **both** the C and C++ recipes — a C++-only flag compiles
and then fails at link on `crypto_x25519`, because Monocypher is C.

**Do not hammer `WiFi.begin()`.** Re-entering it every couple of seconds can
leave the ESP32 unresponsive, which looks exactly like a wedged board. Back
off to ~10 s between join attempts. This is the most likely cause of the
"board wedged" episodes during development.

**`WiFi.scanNetworks()` right after a failed join returns 0.** It is an
artifact of the attempt in flight, *not* a dead radio. Diagnosing a dead
radio this way sent us chasing a hardware fault that did not exist; scan from
a clean state, or check `WiFi.firmwareVersion()` first. Any code that acts on
a scan while disconnected must treat an empty result as **inconclusive** --
`crypto_pub` does, because the first version of its "SSID not on the air"
LED state reported a confident false negative for exactly this reason.

**A phone hotspot goes to sleep.** iOS stops broadcasting the AP once a
laptop is attached and no WiFi client is using it. The board then cannot see
the SSID at all — which is why `crypto_pub`'s LED distinguishes "SSID not on
the air" from "cannot join".

**Uploads need the running sketch's USB stack.** The 1200 bps touch is
serviced by the sketch, so a hung sketch cannot be reflashed; RESET is not
always enough and the cable may have to come out. CMSIS-DAP cannot substitute
— the UNO R4 WiFi only wires its debug interface to the RA4M1 when the DEBUG
jumper is shorted, so `openocd` fails with `CMSIS-DAP command CMD_INFO
failed`.

**A sketch that reports once and then blocks is unobservable.** A terminal
attached a second late sees nothing, which is indistinguishable from a dead
board. Print status on a loop, not once in `setup()`.

**`mads echo`'s stdout is block-buffered when redirected.** A run killed by a
signal loses the buffer and looks exactly like a broker that relayed nothing.
Give it a pty: `script -q /dev/null mads echo --jsonl`.

**Interrupts push onto the same stack on Cortex-M.** Any code that paints or
walks the free stack region must mask interrupts first, or an ISR firing
mid-sweep has its live frame overwritten and returns to a corrupted address.

---

## Broker-side setup for CURVE development

```sh
mads --keypair=uno_r4                     # uno_r4.key + uno_r4.pub
cp uno_r4.pub "$(mads -p)/etc/"           # or wherever --keys_dir points
mads broker --crypto -s mads.ini --keys_dir=/path/to/keys
```

* **Restart the broker** after adding a `.pub` — it scans `*.pub` only at
  startup, and a broker that missed the restart rejects the board exactly as
  if the key were unknown.
* Set `[broker] auth_verbose = true`; the ZAP handler then logs
  `granted` / `DENIED` per attempt, which is the only usable diagnostic.
* `--keys_dir` takes `=` syntax (`--keys_dir=/path`), being an
  optional-value option.
* A non-empty `[broker] ip_whitelist` is **exclusive**, so a DHCP-addressed
  board fails intermittently. Leave it empty while developing.
* All three sockets get CURVE, the settings ROUTER included — there is no
  unencrypted bootstrap.

Running a second broker on other ports (919x) is a convenient way to test
CURVE without disturbing a plain one on 909x.

---

## Open questions

* **`subscribe()`'s return value.** It returns `false` both for "topic stored,
  link not up yet" (a documented success) and "topic table full" (a real
  failure), so a caller cannot tell them apart. Pre-existing; changing it is a
  public API change.
* **`recv_greeting()` compares only the mechanism name**, not libzmq's full
  20-byte zero-padded field, so a peer advertising `NULLX` would be accepted.
  Making it strict costs ~30 bytes in the *disabled* build, which the
  footprint criterion does not allow.
* **The ~30.6 ms fixed publish cost**, above.
* **`ensure_wifi()` is on the publish path**, so a board that loses WiFi
  re-enters `WiFi.begin()` at the reconnect interval. Given the hammering
  caveat above, the 1 s default may be too aggressive for that specific case.
