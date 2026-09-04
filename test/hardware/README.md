# Hardware diagnostics

Sketches that need a real UNO R4 WiFi. Everything here is a *measurement*,
not a test with a pass/fail exit code -- read the output.

## `phase8_diag`

CURVE_PLAN.md Phase 8 steps 1-3, i.e. the parts that need neither a broker
nor WiFi:

1. **TRNG gate** -- `entropy_init()`, then 4 KB of `entropy_fill()` output
   dumped as hex. The sketch judges the two things it can judge from a
   single run (not constant; no repeated 16-byte block) and emits the whole
   dump so the third -- *different across power cycles* -- can be checked by
   comparing two captures offline.
2. **Stack high-water** -- paints the free gap between the heap break and
   the live stack, runs the crypto, then reports how far down the stack
   actually reached.
3. **Timing** -- `box_beforenm()` (one X25519 + HSalsa20), averaged over 16.

Phase 8 steps 4 and 5 need a completed CURVE handshake (Phases 4-5) and a
`mads broker --crypto`, so they are not here yet.

### Building and running

`MADS_ENABLE_CURVE` has to reach the **C** compiler as well as the C++ one:
Monocypher is C, and without the define `monocypher_unit.c` compiles to
nothing and the link fails on `crypto_x25519`.

```sh
arduino-cli compile --upload -p /dev/cu.usbmodemXXXX \
  --fqbn arduino:renesas_uno:unor4wifi --library . \
  --build-property "compiler.cpp.extra_flags=-DMADS_ENABLE_CURVE" \
  --build-property "compiler.c.extra_flags=-DMADS_ENABLE_CURVE" \
  test/hardware/phase8_diag
```

The sketch runs nothing on its own: it waits for a `g` byte on Serial and
runs one pass per `g`. That is deliberate -- reading it straight from
`setup()` races the host opening the port, and whatever is printed first is
lost.

Any serial terminal works. Two notes if you script the capture:

* `stty` settings do not survive `cat` reopening the device, so
  `stty -f PORT ...; cat PORT` produces garbage. Hold one descriptor open
  instead: `(stty 115200 raw -echo; cat) < PORT`.
* **DTR does not reset the UNO R4 WiFi.** Toggling it gets you a second run
  on the same boot, which is *not* a power-cycle test -- `boot millis at
  run` in the output tells you which you got. Re-uploading does reset the
  MCU; pulling the USB lead is the only true power cycle.

### Results on 2026-09-04 (see CURVE_HANDOFF.md Sec 5 and Sec 1)

TRNG passed: across 16 KB from four runs -- two cold boots, one repeat run,
and one true power cycle -- 1024/1024 distinct 16-byte blocks, entropy
7.9875 bits/byte, bit balance 0.4987, lag-1 correlation +0.0014. The
power-cycled run shares zero 16-byte blocks *and* zero 8-byte windows with
any earlier run.

One X25519 costs **45.4 ms** (identical to the microsecond on all four runs
despite different keys each time -- constant-time, as it should be); the
stack reached **1612-1668 bytes** below `__StackTop` against a **20436-byte**
free gap.
