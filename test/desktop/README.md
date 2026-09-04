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
  decode.
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

Compiles every `src/mads/*.cpp` (and `src/mads/crypto/*.cpp` once present)
at `-O0 -fno-inline -fstack-usage`, builds a call graph from the resulting
disassembly, and reports the heaviest root-to-leaf stack sum -- see
`stackreport.py`'s module docstring for exactly what this does and does not
account for (it is a budgeting aid for CURVE_PLAN.md Sec 7.2's 512-byte
`curve_handshake` limit, not a formal proof).

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
