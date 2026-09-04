# CURVE work -- handoff to the machine with a real broker

Written 2026-09-04 at the end of Phases 0-3, from a cloud container with **no MADS broker and no
Arduino board**. You are picking this up on a machine that has at least the broker. Read
[CURVE_PLAN.md](CURVE_PLAN.md) for the specification and [CURVE.md](CURVE.md) for the reasoning;
this file is only the things that do not survive a change of machine.

Delete this file once Phase 5 is verified against a real broker. It is scaffolding, not
documentation.

---

## 1. Do not start with Phase 4

Three acceptance criteria from Phases 0-3 are still open, and two of them are things only your
machine can close. Closing them first is not bureaucracy -- one of them validates the entire
Phase 1 refactor, which everything after it is built on.

**1. `test_zmtp_null` has never run against a broker.** This is the single most important thing to
do first. Phase 1 rewrote every ZMTP call site in `mads_agent.cpp` from `ZmtpCodec`'s static
functions to `ZmtpSession`, including converting `fetch_settings()`'s ini-text frame to the
streaming trio. It compiles, it passes ASan/UBSan, and **it has never exchanged a byte with a real
broker.** If that refactor broke the NULL path, you would not find out until Phase 5's live tests,
with three phases of crypto layered on top of the fault.

```sh
cd test/desktop
MADS_BROKER_HOST=127.0.0.1 make test ARDUINOJSON_DIR=/path/to/ArduinoJson/src
```

against a plain (non-`--crypto`) broker. Also run `mads echo --jsonl` on the same broker to confirm
the published messages decode. Only then move on.

**2. `pub_sub` misses Phase 1's flash budget by 16 bytes** (+48 vs the ±32 criterion; RAM is fine
at +8 everywhere, which is exactly the two `Transport &` references). Root-caused to the SUB-path
call sites plus the mandatory `fetch_settings()` conversion; the fix considered and rejected was
reordering `Agent`'s members so `_pub_session` reclaims the offset-0 codegen the embedded
`_pub_transport` used to get -- fragile, and it silently regresses the next time a member is added.
Re-measure with *your* toolchain versions before deciding whether to care. The numbers here came
from arduino-cli 1.2.2 / `arduino:renesas_uno@1.6.0` / ArduinoJson 7.4.3, and a different core
version may move them either way.

**3. Board TRNG behaviour is unverified.** `entropy_ra4m1.cpp` *links* -- proven by compiling a
throwaway sketch that actually calls `entropy_init()`/`entropy_fill()`, so `--gc-sections` could
not drop the file before the linker had to resolve `HW_SCE_McuSpecificInit` and
`HW_SCE_GenerateRandomNumberSub`. That confirms `arduino:renesas_uno@1.6.0`'s `libfsp.a` exports
them. It does **not** confirm the TRNG produces good bytes, which is Phase 8's gate. If you have a
board, doing Phase 8 step 1 early is cheap and de-risks everything.

---

## 2. Where the work is

Branch `feat/curve-impl`, on `MADS-NET/arduino_mads`, cut from `feat/curve-feasibility` so the
plan documents travel with the code.

| commit | phase |
|---|---|
| `2d60be3` | 0 -- desktop test harness |
| `57c6168` | 1 -- `ZmtpCodec` -> `ZmtpSession` refactor, NULL only |
| `7942acf` | 2 -- crypto primitives |
| `8828c77` | 3 -- entropy |
| `f43ee2a` | plan corrections (see §4) |

Repo owner merges manually; **do not open pull requests**. Commit as
`Paolo Bosetti <paolo.bosetti@unitn.it>`, work on `feat/<desc>` branches.

Reference points used throughout: libzmq **v4.3.5** (what MADS pins in `vendors/CMakeLists.txt`),
MADS at commit `883e361`. If your MADS checkout is newer, re-check `src/main/broker.cpp` and
`src/zap_auth.cpp` before trusting Appendix A.

---

## 3. Environment facts that do not carry over

Everything below was true in the container this was built in, and is not true on your machine.

* **arduino-cli was installed into a scratchpad that no longer exists.** Versions used:
  arduino-cli **1.2.2**, `arduino:renesas_uno@**1.6.0**`, ArduinoJson **7.4.3**, g++ **13.3**.
  Reproduce the footprint numbers with your own and record them.
* **`make test` needs `ARDUINOJSON_DIR`** pointing at ArduinoJson's `src/` directory. Without it
  the Makefile warns and falls back to `/usr/include/ArduinoJson`, which does not exist, and
  `test_zmtp_null` fails to compile while the other binaries build fine -- a confusing partial
  failure. See `test/desktop/README.md`.
* **`build_opt.h` did not work.** With arduino-cli 1.2.2 + core 1.6.0 the sketch never saw
  `MADS_ENABLE_CURVE`. `--build-property "compiler.cpp.extra_flags=-DMADS_ENABLE_CURVE"` worked
  immediately. Plan §7.1 has been reordered accordingly, but this is one data point, not proof.
  Re-test on your setup; Phase 6 must not ship `build_opt.h` as the only enable path without it.
* There is **no MADS broker** here and **no board**. Every "live" test is written, committed, and
  skips cleanly on a missing `MADS_BROKER_HOST`.

---

## 4. Corrections already applied to CURVE_PLAN.md

Do not re-derive these; they are already in the plan (commit `f43ee2a`).

**The Poly1305 keystream split (plan §1 rule 8, Appendix C pitfall 1).** The plan originally said
"block 0 is the Poly1305 key, ciphertext starts at block 1", which reads as the 64-byte block
boundary. That is the RFC 8439 **ChaCha20**-Poly1305 rule. NaCl's XSalsa20-Poly1305 splits at
keystream **byte 32**: bytes 0-31 are the one-time MAC key, bytes 32-63 encrypt the message's
first 32 bytes, and only the remainder comes from block 1 onward. libzmq v4.3.5's
`curve_mechanism_base.cpp` calls libsodium's `crypto_box_easy_afternm`, i.e. exactly this. Taking
the old wording literally would have misaligned every MESSAGE frame by 32 bytes against a real
broker. `nacl_box.{h,cpp}` implement the correct convention, and the NaCl `box.c`/`secretbox.c`
vectors in the suite pass only under it -- that agreement is the evidence, not the assertion.

Also applied: the measured Phase 1 footprint deltas, the `build_opt.h` demotion, and a note that
**6 of the 12 budgeted `#ifdef MADS_ENABLE_CURVE` blocks are spent**, leaving six for Phases 4-6
(the `curve.*` guard, the `z85.*` guard, the `ZmtpSession` mechanism branch, and
`Agent::set_crypto()` plus its members). That is tight but sufficient *if the seam stays where
plan §2 puts it*. Running out is the signal the seam has drifted, not a reason to raise the
budget.

---

## 5. Measurements taken here, with their caveats

### Footprint (arduino-cli 1.2.2, core 1.6.0, ArduinoJson 7.4.3)

| example | flash before -> after Phase 1 | RAM before -> after |
|---|---|---|
| `minimal_pub` | 68904 -> 68936 (+32) | 8748 -> 8756 (+8) |
| `pub_sub` | 69976 -> 70024 (**+48**) | 8908 -> 8916 (+8) |
| `uno_r4_sensor` | 70104 -> 70136 (+32) | 8832 -> 8840 (+8) |

Phase 2 and 3 added **zero** to all three with `MADS_ENABLE_CURVE` undefined -- `--gc-sections`
drops the unreferenced `crypto/*.cpp` object code entirely, and `monocypher_unit.o` compiled
without the macro contains **0 symbols / 32 bytes** (ELF overhead only). These are the numbers
plan §7.3's disabled-build check compares against.

### Stack -- read the caveat, the headline number is misleading

`make stackreport` currently reports a **368-byte** deepest chain (`secretbox_open`). Two reasons
not to trust that against plan §7.2's 512-byte `curve_handshake` budget:

1. It is **x86-64 at `-O0 -fno-inline`**, not `arm-none-eabi` at `-Os`. Frame sizes differ in both
   directions.
2. **`stackreport.py` only walks `src/mads/*.cpp` and `src/mads/crypto/*.cpp` -- it does not
   include `monocypher_unit.c`.** Monocypher is almost certainly the deepest frame in the whole
   handshake and it is invisible in that 368.

Measured separately here with `gcc -O2 -fno-inline -fstack-usage` on the vendored source
(x86-64, so indicative only):

| function | frame |
|---|---|
| `scalarmult` | **432 B** static |
| `crypto_x25519` | 64 B (calls `scalarmult`) |
| `fe_invert` / `fe_mul` | 80 / 128 B |
| **plausible `crypto_x25519` chain total** | **~700 B** |

**This puts plan §7.2's 512-byte budget for `curve_handshake` in doubt before Phase 4 starts.**
The board's reserved main stack is 1 KB (`BSP_CFG_STACK_MAIN_BYTES = 0x400`) with the
stack-pointer monitor disabled, so an overflow corrupts silently rather than faulting. Before
building on that budget: extend `stackreport.py` to include `.c` sources, re-measure on
`arm-none-eabi-gcc -Os`, and if X25519 alone eats the budget, re-base it -- e.g. treat
`crypto_x25519` as a separate line item and require everything *around* it to fit in what remains.
Do not silently exceed it.

For reference, two Monocypher functions that would blow the stack instantly if anything ever pulls
them in: `crypto_argon2` (3424 B) and `crypto_eddsa_check_equation` (1184 B). Both are unused and
dropped by `--gc-sections` today. If a future change references Ed25519 or Argon2, that is a
correctness problem, not a size problem.

---

## 6. Broker-side setup you will need for Phases 4-5

From `src/main/broker.cpp` and `src/curve.hpp` in MADS. Getting any of this wrong produces a
handshake failure indistinguishable from a dropped connection.

1. Generate the client keypair on the PC: `mads --keypair=uno_r4`. Produces `uno_r4.key`
   (private) and `uno_r4.pub`, each a **single 40-character Z85 line with no trailing newline**.
2. Copy `uno_r4.pub` into the broker's keys directory (`$(mads -p)/etc` by default, or whatever
   `--keys_dir` points at).
3. **Restart the broker.** `CurveAuth::fetch_public_keys()` scans `*.pub` only at startup. This
   is the single most common cause of a mysterious `ERROR` reply.
4. Start it with `--crypto` and set `[broker] auth_verbose = true` in `mads.ini`. The ZAP handler
   then prints `granted` / `DENIED` per attempt, which is the *only* usable diagnostic for a
   rejected client.
5. If `[broker] ip_whitelist` is non-empty it is **exclusive** (`zap_auth.cpp:110`). A
   DHCP-addressed board will fail intermittently. Use a reservation or a static address, or leave
   the whitelist empty while developing.
6. All three sockets the client uses get CURVE -- frontend (XSUB), backend (XPUB) **and the
   settings ROUTER** (`broker.cpp:824`). There is no unencrypted bootstrap; `begin()` needs a
   completed handshake before it can read `mads.ini` at all.
7. `mads doctor --crypto` validates the desktop side's key files and can probe a real CURVE
   handshake. Use it to confirm the broker is sane before blaming the board.

---

## 7. Phase 4's golden vectors -- the one procedure worth spelling out

Plan §4.2 asks for recorded HELLO and INITIATE byte strings, generated once from a run verified
against a real `mads broker --crypto`, then committed as the regression net for every later
change. Mechanics:

* Build the desktop test with **both** `-DMADS_ENABLE_CURVE` and `-DMADS_CURVE_TEST_ENTROPY`.
  The latter swaps `entropy_fill()` for a fixed-seed MMIX LCG (`entropy_desktop.cpp`), making the
  transient keypair and vouch nonce reproducible across processes. It carries an `#error`
  tripwire against `ARDUINO`, so it cannot reach a board build.
* **The determinism is over the call *sequence*, not over wall time.** The golden bytes are only
  stable while `curve_handshake()` makes the same `entropy_fill()` calls, in the same order, with
  the same sizes. If you later reorder those calls -- e.g. drawing the vouch nonce before the
  transient key -- the goldens change and that is expected, not a regression. Note the call
  sequence in a comment next to the vectors so a future reader can tell the two apart.
* Record the goldens **only after** the same build (with real entropy) has completed a live
  handshake against a real `--crypto` broker with `auth_verbose` showing `granted`. A golden
  captured from an unverified run just freezes a bug.
* Capture all three socket types (REQ, PUB, SUB) -- the metadata differs by `Socket-Type`.

---

## 8. Things most likely to bite in Phases 4-5

Beyond plan Appendix C, which still applies:

* **MESSAGE frames are ordinary frames** (outer flags `0x00`, or `0x02` when the body exceeds
  255). Only the *handshake* commands carry `0x04`. Setting the command bit on a MESSAGE makes the
  broker treat it as a handshake command and drop the connection.
* **The `FLAG_LARGE` threshold is on the expanded length** (`payload + 33`), not the payload. A
  223-byte payload crosses 255 after expansion. This is easy to test and easy to miss.
* **`skip_frame_body()` must still authenticate.** It discards plaintext; it does not skip the
  MAC. There is no symptom if you get this wrong.
* **`fetch_settings()` hands unauthenticated plaintext to `TomlScan` by design** -- the ini frame
  is multi-KB and streamed. The safety property is that `end_recv_body() == false` must
  `_settings_scan.reset()` and fail the fetch. That call is already wired in from Phase 1 and
  currently always returns true under NULL; Phase 5 makes it meaningful. Do not remove it because
  it "always succeeds".
* **`ZmtpSession::reset()` before every handshake, including reconnects.** Reusing a precom key
  with a restarted nonce counter is catastrophic. Plan §1 rule 2.
* The existing **`send_subscription()` needs no CURVE special-casing** -- it already emits
  `[0x01][topic]` as an ordinary frame body, which is exactly what the broker's downgraded decoder
  expects inside the ciphertext. Keeping the greeting at `minor = 0` is what makes that true.

---

## 9. Open questions for the repo owner

Worth a decision before Phase 6, none blocking Phase 4:

* ~~**Is the 16-byte `pub_sub` flash overshoot acceptable?**~~ **Decided 2026-09-04: yes, not
  worth chasing.** Recorded and closed. Do not spend time reclaiming it.
* ~~**Does `set_reconnect_interval()`'s 1 s default still make sense under CURVE?**~~
  **Reframed 2026-09-04 -- the original question rested on a false premise.** It claimed four
  scalar multiplications per attempt make an *unreachable* broker expensive to retry. It does
  not: `ensure_pub_link()`/`ensure_sub_link()` call `transport.connect()` *before*
  `session.handshake()` and return on failure, so a broker that is down or unroutable costs zero
  X25519. The expensive case is the opposite one -- **TCP connects and CURVE is then rejected**
  (key not in the broker's keys dir, or the broker not restarted after adding it). That is
  deterministic, never self-heals without human action, and under the current logic burns four
  scalar multiplications every interval forever.
  The interval default is therefore the wrong lever. See CURVE_PLAN.md Phase 6's backoff
  requirement for the recommended fix, which does not depend on hardware timing. What still needs
  Phase 8 step 3's per-mult number is only the secondary question of whether a *successful*
  reconnect's added latency is noticeable in `loop()`.
* ~~**On-board key generation**~~ -- **decided 2026-09-04: not doing it.** Keys are generated
  separately with `mads --keypair` and compiled in from `arduino_secrets.h`. Do not re-open this;
  build Phase 6 to it. Note it does not relax the Phase 8 TRNG gate at all -- the transient
  keypair and vouch nonce are still drawn on the board per connection. See CURVE_PLAN.md Phase 6
  for the two consequences that need documenting (one build = one identity; the secret ships in
  plaintext flash).
