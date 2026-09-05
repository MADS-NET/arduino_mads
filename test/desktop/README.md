# Desktop test harness

Builds and runs `src/mads/*.cpp` unmodified on the desktop, against
`arduino_stub/WiFiS3.h` -- a POSIX-socket stand-in that exposes exactly the
surface `wifi_transport.hpp` and `mads_agent.cpp` use. This is what makes the
library's actual production sources runnable under ASan/UBSan without a
board.

## Prerequisites

* `g++` with C++17 and `-fsanitize=address,undefined` support (this was
  developed against g++ 13).
* A local copy of [ArduinoJson](https://arduinojson.org)'s `src/` directory
  (the one containing `ArduinoJson.h`) -- e.g. wherever
  `arduino-cli lib install ArduinoJson` put it
  (`arduino-cli config dump` under `directories.user`, then
  `libraries/ArduinoJson/src`), or a manual clone of
  <https://github.com/bblanchon/ArduinoJson>.
* `python3` and `c++filt` -- only for `make stackreport`.

## Running

```sh
make test ARDUINOJSON_DIR=/path/to/ArduinoJson/src
```

This builds and runs:

* `test_toml_scan` -- pure unit tests of the settings-reply scanner, no
  network involved. Always runs.
* `test_zmtp_null` -- exercises `Mads::Agent::begin()`/`publish()`/
  `subscribe()`/`connect_sub()`/`poll()` against a real `mads broker` over a
  real TCP socket. **Skipped cleanly (exit 0, prints `SKIPPED`) unless
  `MADS_BROKER_HOST` is set** -- there is no broker in this environment, but
  the test is written and committed so it runs wherever one exists:

  ```sh
  MADS_BROKER_HOST=127.0.0.1 make test ARDUINOJSON_DIR=/path/to/ArduinoJson/src
  ```

  Optional: `MADS_SETTINGS_PORT` (default 9092), `MADS_AGENT_NAME` (default
  `test_agent` -- it need not have its own `mads.ini` section),
  `MADS_PUB_TOPIC` (default `test_zmtp_null`). Run `mads echo --jsonl`
  against the same broker in another terminal to see the published messages
  decode -- but note that `mads echo`'s stdout is block-buffered when it is
  redirected to a file, so a run killed by a signal loses whatever is still
  in the buffer and looks exactly like a broker that relayed nothing. Give
  it a pty (`script -q /dev/null mads echo --jsonl`) when capturing to a
  file.

  The round trip is deliberately a publish/poll *loop*: a SUBSCRIBE takes
  time to propagate through the broker's XPUB/XSUB relay (measured at
  ~1.6-1.8 s against a local broker), and anything published before it
  lands is dropped rather than queued -- ZMQ's "slow joiner". A single
  publish followed by polling would fail almost every time.
* `test_crypto_vectors` (once `src/mads/crypto/` exists, Phase 2 onward) and
  `test_entropy` (once `src/mads/entropy_desktop.cpp` exists, Phase 3
  onward) -- built and run automatically once their sources are present;
  absent before that, with no error.

Export `ARDUINOJSON_DIR` once instead of passing it every time if you
prefer:

```sh
export ARDUINOJSON_DIR=/path/to/ArduinoJson/src
make test
```

## `make stackreport`

```sh
make stackreport
```

Compiles every `src/mads/*.cpp` and `src/mads/crypto/*.{cpp,c}` at
`-O0 -fno-inline -fstack-usage`, builds a call graph from the resulting
disassembly and relocations, and reports the heaviest root-to-leaf stack
sum -- see `stackreport.py`'s module docstring for exactly what this does
and does not account for (it is a budgeting aid, not a formal proof).

Pass a substring as a second argument to report one entry point's chain
instead of the heaviest overall:

```sh
OBJDUMP=... CXXFILT=... python3 stackreport.py build/stackreport-arm box_beforenm
```

## `make stackreport-arm`

```sh
make stackreport-arm
```

**This is the one to believe for a board budget.** It builds the crypto
sources with the UNO R4 WiFi's actual toolchain and flags
(`arm-none-eabi-gcc` 7-2017q4, `-Os`, cortex-m4 hard-float, taken from
renesas_uno 1.6.0's `platform.txt`/`boards.txt`). The plain `stackreport`
target is a host build at `-O0`; its frame sizes are much larger and do not
transfer to the board. Scope is the crypto sources only, because they are
freestanding -- `mads_agent.cpp` needs `WiFiS3.h` and ArduinoJson, which
exist only inside a full Arduino build.

Override the toolchain location with `ARM_TOOLCHAIN=/path/to/bin` if the
core is installed somewhere unusual.

What it currently reports, and why it matters, is in DEVELOPER.md
Sec 5: a single `box_beforenm()` (one X25519) is 864 bytes against the
board's 1024-byte main stack.

## `MADS_ENABLE_CURVE`

Pass `MADS_ENABLE_CURVE=1` to `make` to compile the CURVE-guarded test
binaries with `-DMADS_ENABLE_CURVE` (this only affects which sources get
that define on the desktop build; it has no bearing on the board-side
`build_opt.h` mechanism documented in the main README).

## Files

```
arduino_stub/WiFiS3.h   POSIX WiFiClient/WiFi stand-in, millis()/micros()/delay()
arduino_stub/WiFiS3.cpp defines the extern WiFiClass WiFi instance
Makefile                see above
stackreport.py          call-graph stack-usage walker, see `make stackreport`
test_toml_scan.cpp      pure unit tests
test_zmtp_null.cpp      live test against a real broker (NULL mechanism)
test_crypto_vectors.cpp Phase 2: primitive test vectors (added in Phase 2)
test_entropy.cpp        Phase 3: entropy backend smoke test (added in Phase 3)
```
