# CURVE work -- handoff to the machine with a real broker

Written 2026-09-04 at the end of Phases 0-3, from a cloud container with **no MADS broker and no
Arduino board**. You are picking this up on a machine that has at least the broker. Read
[CURVE_PLAN.md](CURVE_PLAN.md) for the specification and [CURVE.md](CURVE.md) for the reasoning;
this file is only the things that do not survive a change of machine.

Delete this file once Phase 5 is verified against a real broker. It is scaffolding, not
documentation.

---

## 1. Do not start with Phase 4

**All three** acceptance criteria from Phases 0-3 are now **closed** (2026-09-04, on the repo
owner's machine, against a live `mads broker` v2.4.3 and a real UNO R4 WiFi). Phase 4 is unblocked as far as these go -- but read Sec 5 before building on plan Sec 7.2's
512-byte `curve_handshake` budget, which is measurably too small and needs re-basing first.

**1. `test_zmtp_null` against a real broker -- CLOSED, and it did fail on first contact.** The
failure was in the *test*, not in the Phase 1 refactor, which is a good outcome: the refactor is
now verified on the wire, and the test that verifies it was itself wrong in two ways (fixed in
commit `85bf650`).

* It asserted `subscribe()` returns true when called *before* `connect_sub()`. It does not, by
  design -- with no SUB link up the topic is only stored for replay and false means "remembered,
  nothing sent on the wire". `subscribe()` is byte-identical on `main`; Phase 1 only swapped
  `ZmtpCodec::send_subscription(_sub_transport, ...)` for `_sub_session.send_subscription(...)`.
* It published once and then polled, racing ZMQ's slow joiner. The SUBSCRIBE has to propagate
  through the broker's XPUB/XSUB relay before anything comes back, and a message published inside
  that window is dropped, not queued. Measured propagation against a local broker is **8-9
  publish/poll iterations, ~1.6-1.8 s** -- so the original single publish could never have
  succeeded however long it polled.

With those fixed the full suite passes under ASan+UBSan with no sanitizer reports:
`test_toml_scan` 65/65, `test_zmtp_null` PASSED, `test_crypto_vectors` 448/448, `test_entropy` and
`test_entropy_deterministic` PASSED. `mads echo --jsonl` decodes the published frames correctly
(`topic=test_zmtp_null`, `type=json`, payload intact). What this exercises end to end: `begin()`
including `fetch_settings()`'s converted streaming trio, `publish()`, both `subscribe()` call
sites, `connect_sub()` and `poll()`.

```sh
cd test/desktop
MADS_BROKER_HOST=127.0.0.1 make test ARDUINOJSON_DIR=/path/to/ArduinoJson/src
```

One trap worth knowing, now noted in `test/desktop/README.md`: `mads echo`'s stdout is
block-buffered when redirected to a file, so a run killed by a signal silently loses the buffer and
is indistinguishable from a broker relaying nothing. Capture it under a pty
(`script -q /dev/null mads echo --jsonl`).

**2. `pub_sub` misses Phase 1's flash budget by 16 bytes** (+48 vs the ±32 criterion; RAM is fine
at +8 everywhere, which is exactly the two `Transport &` references). Root-caused to the SUB-path
call sites plus the mandatory `fetch_settings()` conversion; the fix considered and rejected was
reordering `Agent`'s members so `_pub_session` reclaims the offset-0 codegen the embedded
`_pub_transport` used to get -- fragile, and it silently regresses the next time a member is added.
**Re-measured 2026-09-04 on arduino-cli 1.0.2** (same core 1.6.0 / ArduinoJson 7.4.3), against a
`main` worktree as the pre-Phase-1 baseline. Absolute flash sizes shift by ~40 bytes between the
two arduino-cli versions, but **every delta is identical**: `+32 / +48 / +32` flash and `+8` RAM,
exactly as measured in the container. The overshoot is therefore inherent to the refactor and not a
compiler artifact -- there is nothing toolchain-specific left to hope for. Combined with Sec 9's
decision that the 16 bytes are not worth chasing, **this criterion is closed.**

| example | main (1.0.2) | Phase 3 (1.0.2) | delta | container delta |
|---|---|---|---|---|
| `minimal_pub` | 68944 / 8748 | 68976 / 8756 | +32 / +8 | +32 |
| `pub_sub` | 70024 / 8908 | 70072 / 8916 | **+48** / +8 | +48 |
| `uno_r4_sensor` | 70136 / 8832 | 70168 / 8840 | +32 / +8 | +32 |

Because the current branch includes Phases 2 and 3, these deltas being unchanged from Phase 1's
also re-confirms the **zero**-cost disabled build (plan Sec 7.3) on a second toolchain.

**3. Board TRNG behaviour is unverified.** `entropy_ra4m1.cpp` *links* -- proven by compiling a
throwaway sketch that actually calls `entropy_init()`/`entropy_fill()`, so `--gc-sections` could
not drop the file before the linker had to resolve `HW_SCE_McuSpecificInit` and
`HW_SCE_GenerateRandomNumberSub`. That confirms `arduino:renesas_uno@1.6.0`'s `libfsp.a` exports
them. It does **not** confirm the TRNG produces good bytes, which is Phase 8's gate. If you have a
board, doing Phase 8 step 1 early is cheap and de-risks everything.

**CLOSED 2026-09-04 on a real UNO R4 WiFi.** `test/hardware/phase8_diag` (Phase 8 steps 1-3) was
flashed and run; see `test/hardware/README.md` for how. `entropy_init()` returns OK, so the SCE
TRNG initialises and passes its own health check on hardware, not just at the linker.

Phase 8 step 1's three conditions, over 16 KB from four runs: two cold boots via re-upload, one
second run on an existing boot, and **one true power cycle** (USB lead physically pulled and
replugged). Note that a DTR toggle does *not* reset this board -- it only gets a second run on the
same boot, which tests nothing about power-up state. The sketch prints `boot millis at run` so the
two are always distinguishable.

| condition | result |
|---|---|
| not constant | pass -- no all-zero or all-`0xFF` run |
| no repeated 16-byte block | pass -- **1024/1024 distinct**, zero collisions, including across runs |
| different across power cycles | pass -- see below |

The power-cycled run shares **zero 16-byte blocks and zero 8-byte windows** with any of the three
earlier runs (4089 windows each, no collision at all). So the TRNG does not resume a stream, replay
a power-up state, or seed itself from anything reproducible.

Supporting statistics on the combined 16 KB: Shannon entropy **7.9875 bits/byte** (the
finite-sample ideal at this many samples is ~7.9888), bit balance **0.49866**, lag-1 serial
correlation **+0.00139**, byte chi-square **280.3** on df=255. That chi-square is worth a note: at
12 KB it read 303.4, around the 96th percentile, which was recorded here as mildly high and worth
re-checking with more data. With the fourth run added it fell to 280.3, an entirely ordinary value
-- so that reading was sampling noise, as expected, and is now resolved rather than outstanding.

Treat this as a bring-up gate that the TRNG **passed**, not as a statistical certification: 16 KB
is far too little for that, and NIST SP 800-90B or dieharder over megabytes is what certification
would mean. Nothing here suggests it would be needed.

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

**Confirmed working on the repo owner's machine 2026-09-04** (the numbers above having been
reproduced there): macOS 15 arm64, Apple clang 21, arduino-cli **1.0.2**, core
`arduino:renesas_uno@1.6.0`, ArduinoJson **7.4.3**, MADS **v2.4.3**, ArduinoJson at
`~/Documents/Arduino/libraries/ArduinoJson/src`. The desktop harness builds warning-free under
Apple clang as well as g++ 13.3, and `arm-none-eabi-gcc 7-2017q4` is available under
`~/Library/Arduino15/packages/arduino/tools/` for the Sec 5 stack re-measurement.

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

### Stack -- MEASURED on the board's toolchain 2026-09-04; re-base the budget, but not a blocker

The suspicion recorded here was right, and the reality is worse. `stackreport` was under-reporting
in four independent ways (all fixed in commit `1ed8056`; see that message for the mechanics) -- the
worst being that in an unlinked object every cross-function call disassembles to an unresolved
placeholder pointing at the *caller*, so under `-ffunction-sections` the ARM call graph was nothing
but self-edges and every chain collapsed to one frame. The old 368-byte figure measured almost
nothing.

`make stackreport-arm` now builds the crypto sources with the UNO R4 WiFi's real toolchain and
flags (arm-none-eabi-gcc 7-2017q4, `-Os`, cortex-m4 hard-float, from renesas_uno 1.6.0). Measured
root-to-leaf chains:

| chain | bytes |
|---|---|
| `Mads::box_beforenm` (one X25519 + HSalsa20) | **864** |
| `crypto_x25519` alone | 800 |
| `Mads::secretbox_open` | 688 |
| `Mads::secretbox_seal` | 672 |

Now the part that took a wrong turn on the first pass and is worth stating carefully, because the
scary reading is the wrong one.

`BSP_CFG_STACK_MAIN_BYTES = 0x400` is a **reserved floor, not a ceiling.** In
`variants/UNOWIFIR4/fsp.ld` the heap and the stack grow toward each other from opposite ends of the
same free region: `.heap` starts at `__HeapBase` (immediately after `.bss`) and grows up, the stack
grows down from `__StackTop`, and `__HeapLimit == __StackLimit == __StackTop - 0x400` is only the
guaranteed minimum gap. Linked symbols from a real `pub_sub` build:

| symbol | address |
|---|---|
| `__HeapBase` = `__bss_end__` = `end` | `0x200022f0` |
| `__HeapLimit` = `__StackLimit` | `0x20007b00` |
| `__StackTop` | `0x20007f00` |

So the reserved stack is exactly 1024 B, but there are **22544 bytes** between `__HeapBase` and
`__StackLimit` that the stack may grow into, and roughly 23.5 KB before it would reach `.bss`.
Nothing faults at `__StackLimit`; the stack-pointer monitor is disabled.

That makes the 864 B **not a hard blocker for Phase 4** -- there is ample physical room. Two things
are nevertheless true and need acting on:

1. **Plan Sec 7.2's 512-byte budget for `curve_handshake` is wrong by more than 1.7x** and has to
   be re-based before anything is written against it. `box_beforenm` alone is 864 B, which is 84%
   of the *reserved* region on its own. Re-base it as: `box_beforenm` ~900 B as its own line item,
   everything else in the handshake budgeted separately, and state the total against the 22.5 KB
   shared region rather than against 1 KB.
2. **The real failure mode is a silent stack/heap collision, not a stack overflow.** The stack
   spending 864 B is fine; the stack spending 864 B *while the heap has grown up to meet it* is
   memory corruption with no fault and no symptom. ArduinoJson v7 heap-allocates every
   `JsonDocument`, so this sketch does use the heap, and the margin is whatever is left of those
   22.5 KB. That is a property of the whole sketch, not of `curve_handshake`, so it cannot be
   settled statically.

**Measured on the board 2026-09-04, and it confirms the reading above.** `phase8_diag` paints the
free gap, runs 16 `box_beforenm()` calls, and reports where the paint survived:

| quantity | measured |
|---|---|
| free gap, heap break -> `__StackTop` | **20436 B** |
| reserved stack, `__StackTop` - `__StackLimit` | 1024 B |
| stack high-water below `__StackTop` | **1612-1668 B** |
| ... of which beyond the 1024 B reservation | **588-644 B** |

So the stack really does cross `__StackLimit` in normal operation, silently and without
consequence, which is exactly what "floor, not ceiling" predicts -- and it settles the question
empirically rather than by reading the linker script. Peak usage is about **8%** of the available
gap. The static 864 B for `box_beforenm` plus the diagnostic's own frames (the key buffers, the
loop, and `main`/`loop` underneath) accounts for the 1612 well enough to trust both numbers.

The remaining risk is unchanged and still cannot be settled statically: this was measured with a
sketch that barely touches the heap, whereas a real agent allocates a `JsonDocument` per publish.
Re-run this measurement in Phase 8 with the actual agent running, when there is a handshake to
measure.

Raising `BSP_CFG_STACK_MAIN_BYTES` is *not* the fix and was wrongly listed as an option here
earlier: it lives in the core's variant files (so a library cannot set it), and since the limit is
a floor rather than a ceiling, raising it would only take space away from the heap.

For reference, the two Monocypher functions that would blow the stack instantly if anything ever
pulled them in: `crypto_argon2` (2992 B chain) and `crypto_eddsa_check` (1720 B). Both are unused
and dropped by `--gc-sections` today. If a future change references Ed25519 or Argon2 that is a
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
  requirement for the recommended fix, which does not depend on hardware timing.

  **The per-mult number is now measured: one `box_beforenm()` (a single X25519 plus HSalsa20)
  takes 45.4 ms on the board** -- 45449 us, or about 2.18M cycles at the RA4M1's 48 MHz (HOCO
  48 MHz, PLL /4 x12, ICLK /1). Plausible for portable C rather than hand-written Cortex-M4
  assembly. Worth noting as a side benefit: that figure came back **identical to the microsecond
  across all three runs even though each drew a different key**, which is what a constant-time
  scalar multiplication should do and is a small piece of evidence that Monocypher is not leaking
  the secret scalar through timing. At the four scalar multiplications a CURVE handshake needs, that
  is roughly **180 ms of blocking compute per handshake attempt**, on top of the TCP connect. So
  the secondary question answers itself: a successful reconnect stalls `loop()` for about a fifth
  of a second, which is very visible for an agent sampling at 100 ms (`[uno_r4] delay = 100` in
  `mads.ini`) -- it will drop roughly two samples per reconnect. Worth documenting in Phase 9, and
  worth keeping in mind if anyone proposes retrying a rejected handshake aggressively: the
  rejected case burns the same 180 ms and never succeeds, which is the whole argument for the
  Phase 6 backoff.
* **New, surfaced by the first live run: is `subscribe()`'s return value the contract you want?**
  It returns `false` for two unrelated situations -- "topic stored, link not up yet, nothing sent"
  (a success per the header's documented "safe to call before `connect_sub()`") and "topic table
  full, not remembered" (a real failure). A caller cannot tell them apart, and the natural
  `if (!agent.subscribe(t)) { error }` is wrong against a link that simply is not up yet -- which
  is exactly the mistake the committed test made. This is **pre-existing on `main`**, not something
  Phase 1 introduced, and changing it is a public API change affecting existing sketches, so it was
  left alone. Options: return true when the topic is durably stored (arguably what the docs already
  promise), or split "stored" from "sent" into a small enum. Worth settling before Phase 6
  documents the CURVE-era API, since CURVE makes "link not up yet" much more common.

* ~~**On-board key generation**~~ -- **decided 2026-09-04: not doing it.** Keys are generated
  separately with `mads --keypair` and compiled in from `arduino_secrets.h`. Do not re-open this;
  build Phase 6 to it. Note it does not relax the Phase 8 TRNG gate at all -- the transient
  keypair and vouch nonce are still drawn on the board per connection. See CURVE_PLAN.md Phase 6
  for the two consequences that need documenting (one build = one identity; the secret ships in
  plaintext flash).
