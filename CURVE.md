# CURVE encryption on the UNO R4 WiFi -- feasibility study

> **Implemented, 2026-09-05.** This document is the original feasibility
> study and is kept as the reasoning record, not as documentation of what
> was built. CURVE now works and is verified on hardware against a real
> `mads broker --crypto` — see [README.md](README.md) to use it and
> [DEVELOPER.md](DEVELOPER.md) for internals and measurements.
>
> What the study got right: the wire layout, the choice of Monocypher over
> TweetNaCl (whose `crypto_scalarmult` frame would not have fitted), and the
> judgement that the flash and RAM cost was affordable.
>
> What it got wrong, all corrected in [DEVELOPER.md](DEVELOPER.md):
> the RAM estimate was about 5x low (~1.9 KB actual, not ~300 B) and flash
> about 5 KB low; the 1 KB "main stack" turned out to be a guaranteed floor
> rather than a ceiling, with ~20 KB actually available; and the performance
> question was framed around the cost of the crypto, which is negligible —
> publish latency is set almost entirely by how many times the sketch writes
> to the WiFi module.



Status: **study only, no code**. The implementation plan derived from it is
[DEVELOPER.md](DEVELOPER.md). This document is the result of reading the exact wire behaviour
out of libzmq v4.3.5 (the version MADS pins in `vendors/CMakeLists.txt`) and out of the MADS
broker's own CURVE/ZAP setup, and costing it against this library's measured footprint. It says
what would have to be built, what it would cost, and where it can go wrong.

## Verdict

Feasible, and cheaper in flash/RAM than it looks. The elliptic-curve maths is *not* the hard part:
it is four X25519 scalar multiplications per connection and a vendored library.

The three things that actually make this a non-trivial change:

1. **CURVE is a framing change, not an add-on.** Once the handshake completes, every ZMTP frame in
   both directions is re-wrapped as an encrypted `MESSAGE` command, and the multipart `MORE` bit
   moves *inside* the ciphertext. `ZmtpCodec`'s current design -- stateless `static` functions over
   a `Transport &` -- cannot express that: nonce counters and the precomputed shared key are
   per-connection state. Every call site in `mads_agent.cpp` is touched.
2. **The zero-copy blob publish path does not survive unchanged.** `publish(const uint8_t *,
   size_t, JsonDocument &)` currently writes the caller's buffer straight to the socket, so blob
   size is bounded by the link rather than by RAM. NaCl `secretbox` puts the Poly1305 tag *before*
   the ciphertext, so a single forward pass is impossible. There is a clean fix (§7), but it is a
   real design change to the library's headline RAM property.
3. **Everything rests on a CSPRNG the Arduino core does not expose.** CURVE needs a fresh random
   transient keypair and a random vouch nonce per connection. `random()` on the Renesas core is a
   deterministic LCG; using it would silently reduce CURVE to no forward secrecy at all, with no
   visible symptom. There is a way out (§5) but it needs hardware verification before anything
   else is worth writing.

Uncomfortable framing point, separate from feasibility: a private key sitting in plaintext sketch
flash on a board with an open bootloader is transport security, not device identity. Anyone with
five minutes of physical access owns that agent's credentials permanently. That is a legitimate
trade -- it is exactly what CURVE buys you against a *network* attacker -- but it should be a
stated assumption, not an accident.

## 1. What the MADS broker actually requires

From `src/main/broker.cpp` and `src/curve.hpp` in the MADS repo:

* Under `--crypto`, CURVE server is enabled on **all three** sockets the board talks to:
  `frontend` (XSUB), `backend` (XPUB) *and* `settings_router` (ROUTER, `broker.cpp:824`). There is
  no "encrypt the data path but fetch settings in the clear" half-step -- `begin()` needs the
  handshake before it can read `mads.ini` at all.
* Authorisation is ZAP (`src/zap_auth.cpp`). The broker's `CurveAuth::fetch_public_keys()` scans
  the keys directory for `*.pub` files at startup and allow-lists every Z85 key it finds. The
  board's public key must therefore be a `.pub` file in that directory **and the broker must be
  restarted** -- the scan is start-up only.
* `ZapAuth::_authorise()` also enforces `[broker] ip_whitelist` when it is non-empty
  (`zap_auth.cpp:110`). A DHCP-addressed board will fail authentication intermittently against a
  whitelisted broker; use a DHCP reservation or a static address.
* Key files are a single 40-character Z85 line with no trailing newline
  (`zap_auth.cpp:205`, `mads.cpp:169`). The board needs a ~25-line Z85 decoder to get back to the
  raw 32 bytes.
* `[broker] auth_verbose = true` makes the ZAP handler print `granted`/`DENIED` per attempt. That
  is the only realistic way to debug a rejected board, because a CURVE failure on the wire is
  indistinguishable from a dropped connection.

Deployment shape that follows: generate the board's keypair **on the PC** with
`mads --keypair=uno_r4`, copy `uno_r4.pub` into the broker's keys dir, restart the broker, and
paste both Z85 strings into the sketch's `arduino_secrets.h`. This knowingly breaks CRYPTO.md's
"the private key shall never be moved from the device where it was generated" rule; on-board key
generation would honour it, but only once §5 is settled.

## 2. The wire protocol, exactly

Verified against libzmq v4.3.5 `src/curve_client_tools.hpp`, `src/curve_client.cpp`,
`src/curve_mechanism_base.cpp`, `src/zmtp_engine.cpp`. Byte offsets below are the real ones, not
the RFC's prose.

**Greeting** -- as today, but bytes 12..16 become `CURVE` (zero-padded to 16), `as-server = 0`.
Keeping `minor = 0` is still correct and still worth doing: `zmtp_engine.cpp:390` shows
`handshake_v3_0()` calls `handshake_v3_x(true)`, i.e. `downgrade_sub = true`, which keeps
SUBSCRIBE as a `0x01`-prefixed ordinary frame rather than a ZMTP 3.1 command. The existing
`send_subscription()` body needs no change at all -- it just gets encrypted like anything else.

**HELLO** -- command frame (outer flags `0x04`), body exactly 200 bytes:

| offset | len | content |
|---|---|---|
| 0   | 6  | `\x05HELLO` |
| 6   | 2  | `\x01\x00` (CURVE version 1.0) |
| 8   | 72 | zeros (anti-amplification padding) |
| 80  | 32 | `C'` -- client transient public key |
| 112 | 8  | short nonce, big-endian `uint64` |
| 120 | 80 | `crypto_box(64 zero bytes)` under nonce `"CurveZMQHELLO---" \|\| short`, to `S`, from `c'` |

**WELCOME** -- command frame, body exactly 168 bytes: `\x07WELCOME` (8) + 16-byte long nonce +
144-byte box opened under `"WELCOME-" || long` with the **same** `(S, c')` pair as HELLO. Plaintext
is `S'` (32) + cookie (96).

**INITIATE** -- command frame, body `113 + 128 + 16 + len(metadata)`:
`\x08INITIATE` (9) + cookie echoed verbatim (96) + short nonce (8) + box under
`"CurveZMQINITIATE" || short` to `S'` from `c'`, whose plaintext is
`C` (32) + vouch nonce tail (16) + vouch box (80) + metadata. The vouch box is
`crypto_box(C' || S)` under `"VOUCH---" || 16 random bytes`, to `S'`, from `c` -- this is the only
place the board's *permanent* secret key is used, and the only place that needs randomness besides
the transient keypair. Metadata is the same `Socket-Type` property the current `send_ready()`
already builds.

**READY** -- command frame, `\x05READY` (6) + short nonce (8) + box opened with the precomputed
`(S', c')` key under `"CurveZMQREADY---" || short`. `ERROR` (`\x05ERROR` + 1-byte reason length +
reason) must be handled here too: that is where an unrecognised client key surfaces.

**MESSAGE** -- and this is the part that is easy to get wrong. It is **not** a command frame.
`stream_engine_base.cpp:601 pull_and_encode()` does not set `msg_t::command`, and
`curve_encoding_t::encode()` re-inits the message, so the outer ZMTP flags byte is `0x00`
(or `0x02` when the body exceeds 255 bytes). Body:

```
"\x07MESSAGE" (8) || short nonce (8) || Poly1305 tag (16) || XSalsa20(flags_byte || payload)
```

with the nonce prefix `"CurveZMQMESSAGEC"` for board→broker and `"CurveZMQMESSAGES"` for
broker→board. `flags_byte` carries `MORE` (`0x01`) and `COMMAND` (`0x04`). Overhead is a flat
**33 bytes per frame**.

**Nonces.** One `uint64` counter per connection, starting at 1, shared across HELLO (1),
INITIATE (2), and then every MESSAGE (3, 4, ...). Big-endian. Incoming MESSAGE nonces must be
*strictly* increasing (`curve_mechanism_base.cpp:100`); implementing that check on our side is what
buys replay protection, and skipping it is a silent downgrade.

## 3. Consequences for `ZmtpCodec`

* `handshake_null()` gains a sibling `handshake_curve()`, and both need somewhere to leave
  per-connection state. The natural shape is a small `ZmtpSession` owning `Transport &` plus an
  optional `CurveState`, with `send_frame`/`recv_frame_header`/`recv_frame_body` becoming member
  functions. `Transport` itself is untouched.
* **`skip_frame_body()` becomes crypto-aware.** Today it discards bytes. Under CURVE the `MORE`
  bit that tells `poll()` where the message ends is inside the ciphertext, so a frame we intend to
  drop must still be decrypted far enough to read `flags_byte`, and should still be run through
  Poly1305 so a dropped frame cannot be forged. This is the single easiest thing to overlook.
* The frame-length header we write must account for the 33-byte expansion before the body is
  produced. That is fine -- the expansion is a constant.

## 4. Crypto primitives and library choice

Needed: X25519, HSalsa20 (for `crypto_box_beforenm`), XSalsa20, Poly1305, plus `secretbox` glue.

Two credible options:

**Monocypher (recommended).** Public domain / BSD, portable C, constant-time, gives X25519 and
Poly1305 directly. It does *not* ship Salsa20 -- its key exchange uses HChaCha20 -- so ~150-200
lines of Salsa20 core + HSalsa20 + XSalsa20 have to be written. That is well-trodden, testable
code, and NaCl publishes test vectors for all of it.

**TweetNaCl.** ~800 lines, one file, public domain, and exposes *precisely* the API CurveZMQ is
specified against (`crypto_box`, `crypto_box_open`, `crypto_box_beforenm`, `crypto_box_afternm`),
so the glue nearly disappears. The cost is speed: its 16-limb `i64` field arithmetic is roughly an
order of magnitude slower than Monocypher's. [Likely] that turns a ~0.6 s `begin()` into several
seconds -- painful, since the same cost is paid again on every reconnect.

Recommendation: Monocypher, with TweetNaCl kept as the reference implementation to cross-check
against during development on the desktop build.

Scalar multiplication count per connection: 1 to generate `c'/C'`, 1 for `beforenm(S, c')` (shared
between the HELLO box and the WELCOME open -- cache it, do not compute it twice), 1 for
`beforenm(S', c')`, 1 for the vouch box to `S'` from `c`. **Four.** `begin()` opens three
connections, so twelve per cold start.

## 5. The randomness problem

This gates everything else. CURVE's forward secrecy is exactly as good as the entropy behind `c'`;
a predictable transient key lets a passive attacker who later obtains `S`'s secret -- or who can
simply guess the counter -- recover session keys, and nothing about the connection looks wrong.

The Renesas core's `random()` is an LCG. `analogRead()` noise and `micros()` jitter are not
sufficient on their own.

**Finding, and the reason this is worth pursuing:** the RA4M1's Secure Crypto Engine TRNG *is*
already linked into every UNO R4 sketch. `variants/UNOWIFIR4/libs/libfsp.a` in
`arduino/ArduinoCore-renesas` defines `HW_SCE_McuSpecificInit` and `HW_SCE_GenerateRandomNumberSub`
(in member `hw_sce_p09.o`). The FSP `r_sce.h` public header is not shipped with the core, but the
symbols are there and can be declared `extern "C"` directly:

```cpp
extern "C" {
  void      HW_SCE_McuSpecificInit(void);
  fsp_err_t HW_SCE_GenerateRandomNumberSub(uint32_t *out /* 4 words = 16 bytes */);
}
```

[Likely, not verified on hardware] this works after a single `HW_SCE_McuSpecificInit()` call. It
must be proven on a board before anything is built on it -- including checking that the SCE module
stop bit is cleared, and running a crude sanity check (never all-zero, never repeating across
resets) at startup.

Fallback if the TRNG turns out to be unreachable: a hedged DRBG seeded from the *permanent secret
key* (already high-entropy and already on the device) plus a reboot counter persisted in the R4's
data-flash `EEPROM` library, plus jitter. That is cryptographically defensible, but it makes
counter persistence safety-critical -- a counter that resets repeats a transient key, which is
catastrophic. Prefer the TRNG.

## 6. Resource budget

Baseline, measured and recorded in the README for `examples/uno_r4_sensor`: ~70 KB flash (26% of
262,144) and ~8.8 KB global RAM (26% of 32,768), leaving ~24 KB RAM free.

| item | estimate | confidence |
|---|---|---|
| Monocypher X25519 + Poly1305, after `--gc-sections` | 6-9 KB flash | Guessing |
| Salsa20 / HSalsa20 / XSalsa20 | ~1 KB flash | Guessing |
| CURVE state machine, Z85 decode, session plumbing | ~3 KB flash | Guessing |
| **flash total** | **~10-13 KB → ~82 KB (31%)** | Guessing |
| persistent CURVE state, 3 links + keys | ~300 B global RAM | Likely |
| peak handshake stack if written naively (buffers + X25519 scratch) | ~1.2-1.5 KB | Guessing |
| X25519 scalar mult @ 48 MHz | 40-125 ms | Guessing -- **measure** |
| `begin()` handshake cost, 12 scalar mults | ~0.5-1.5 s | Guessing |
| XSalsa20+Poly1305 on a 256-byte message | <0.2 ms | Likely |

Flash and global RAM are comfortable. Two numbers are not.

**Stack.** [Certain] `variants/UNOWIFIR4/includes/ra_cfg/fsp_cfg/bsp/bsp_cfg.h` sets
`BSP_CFG_STACK_MAIN_BYTES = 0x400` -- 1 KB of reserved main stack -- and `cores/arduino/main.cpp`
runs `setup()`/`loop()` directly on it. It also disables the stack-pointer monitor
(`R_MPU_SPMON->SP[0].CTL = 0`), so an overflow does not fault; it silently corrupts whatever lies
below. In practice the usable stack is bounded by the gap to the top of the 8 KB heap rather than
by the reserved 0x400, so more than 1 KB often works -- but nothing checks it and nothing warns.
A handshake written with its buffers as ordinary locals would sit right on that boundary. The
buffers must be file-static (inside the opt-in guard, so disabled builds pay nothing), and the
result must be measured with `-fstack-usage`.

This also settles the library choice on its own: TweetNaCl's `crypto_scalarmult` puts `i64 x[80]`
(640 B) plus six 128-byte `gf` locals in a single frame -- roughly 1.4 KB -- which does not fit
here at all. Monocypher is not merely the faster option, it is the one that fits.

**Scalar multiplication time.** It lands entirely in `begin()` and in the reconnect path, which
already blocks `loop()` on `WiFiClient::connect()`.

[Certain, corrected 2026-09-04] An earlier version of this paragraph said the four extra scalar
mults make an *unreachable* broker more expensive to retry. They do not: `ensure_pub_link()` and
`ensure_sub_link()` call `transport.connect()` before `session.handshake()` and return on failure,
so a down or unroutable broker never reaches any crypto. The costly case is the inverse -- TCP
connects and the CURVE handshake is then *rejected*, which is what a mis-provisioned key looks
like. That failure is deterministic and never self-heals, so retrying it once per second forever
is pure waste; the fix is backoff keyed on that specific error, not a larger fixed interval.

## 7. The blob publish path

`publish(const uint8_t *blob, size_t, JsonDocument &)` deliberately writes the caller's buffer
straight to the link, so blob size is bounded by the network rather than by this library's RAM.
NaCl `secretbox` emits `tag || ciphertext`, and the Poly1305 tag covers the whole ciphertext, so
the tag cannot be written until the last plaintext byte has been processed. A single forward pass
is impossible.

The fix that preserves the property: **two passes over the caller's buffer**, which is legitimate
because the caller hands us a stable `const uint8_t *`.

1. Pass 1 -- generate the XSalsa20 keystream and feed the resulting ciphertext into Poly1305,
   discarding the ciphertext. Yields the tag.
2. Write the frame header, `\x07MESSAGE`, the nonce, and the tag.
3. Pass 2 -- regenerate the same keystream from the same nonce and write the ciphertext out in
   fixed-size chunks.

Cost is one extra Salsa20 pass: [Likely] ~2.5 ms for a 4 KB blob at 48 MHz, and zero extra RAM.
The alternative -- buffering the blob to encrypt it once -- would cap blob size at a couple of
kilobytes and throw away the one thing that path was designed for.

Receive side is easier: `poll()` already bounds the payload by `payload_cap`, so the frame can be
read in full and decrypted in place. One wrinkle: the plaintext is `flags_byte || payload`, so
either the buffer needs one spare byte or the decrypted payload needs a 1-byte `memmove`.

## 8. Making it opt-in

MADS makes CURVE opt-in at run time; here it should be opt-in at *compile* time, so sketches that
do not want it pay nothing. A `#define` in the `.ino` will not work -- the Arduino builder compiles
library sources in a separate translation unit -- and `--gc-sections` cannot drop code reached
through a runtime flag.

The workable mechanism is `build_opt.h` in the sketch folder (supported by both the IDE and
arduino-cli):

```
// build_opt.h
-DMADS_ENABLE_CURVE
```

with everything crypto-related inside `#ifdef MADS_ENABLE_CURVE`, and `begin()` gaining an
optional `CurveKeys` argument that only exists under that macro. Sketches that never define it
compile byte-identically to today.

## 9. What stays out of scope

* On-board key generation. **Settled: not doing it.** Keys are generated with
  `mads --keypair` on a PC and embedded at compile time from `arduino_secrets.h`. This
  knowingly departs from CRYPTO.md's "the private key shall never be moved from the device
  where it was generated"; see DEVELOPER.md for the consequences. It does **not**
  remove the need for a real TRNG -- the per-connection transient keypair and vouch nonce
  are still generated on the board (§5).
* CURVE *server* mode -- the board is only ever a client.
* Certificate/key rotation, revocation, or any key storage beyond a header file.
* PLAIN and GSSAPI -- MADS refuses them anyway (`zap_auth.cpp`).

## 10. Suggested order of work

1. **Prove the TRNG on hardware.** Declare the two `HW_SCE_*` symbols, dump 4 KB, check it is not
   constant and does not repeat across resets. If this fails, stop and reconsider -- everything
   below inherits its security from here.
2. **Build the primitives against test vectors on the desktop**, not on the board. `mads_agent.cpp`
   already compiles for the desktop against a POSIX-socket stand-in for `WiFiS3.h` (the README
   documents this for the blob work); reuse that. Cross-check Monocypher+Salsa20 against TweetNaCl
   on NaCl's published vectors.
3. **Refactor `ZmtpCodec` into a session object** with NULL still the only mechanism. This is a
   pure no-behaviour-change step and should be verifiable against a real broker before any crypto
   is involved.
4. **Implement the handshake and MESSAGE framing**, desktop-first against a real
   `mads broker --crypto`. `auth_verbose = true` on the broker is the debugging channel.
5. **Port to the board and measure** -- flash, RAM, and the scalar multiplication timing that all
   the §6 estimates hang on.
6. **Then** the two-pass blob path, which is an optimisation over a working implementation, not a
   prerequisite.

Steps 1 and 3 are independent of each other and both cheap; either is a reasonable place to find
out early whether this is worth continuing.
