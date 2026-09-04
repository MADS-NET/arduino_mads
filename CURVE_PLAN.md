# CURVE support -- implementation plan

Companion to [CURVE.md](CURVE.md), which is the feasibility study and the authority on *why*.
This document is the authority on *what to build and in what order*. Read CURVE.md first;
Appendix A here repeats the wire layouts in table form so you do not have to.

**Audience: an implementing agent.** Everything below is meant to be executed literally. Where a
step says "do not", it is because the obvious alternative is wrong in a way that will not show up
until hardware bring-up.

---

## 0. Rules of engagement

1. Work on a `feat/<desc>` branch. Do not open pull requests. Commit as
   `Paolo Bosetti <paolo.bosetti@unitn.it>`.
2. Phases are ordered by dependency. Each has an **Acceptance** block. Do not start a phase until
   the previous one's acceptance holds. Commit at each phase boundary.
3. Phases 0-7 require **no hardware**. Phase 8 does, and is a human task -- prepare it, do not
   attempt to fake it.
4. If you cannot satisfy an acceptance criterion, stop and say so. Do not weaken the criterion.
5. Never invent a wire detail. Every byte offset you need is in Appendix A, taken from libzmq
   v4.3.5. If something is missing, read libzmq v4.3.5 -- not the RFC, not memory.

---

## 1. Non-negotiables

These are correctness and security invariants. Violating any of them produces code that appears to
work and is broken.

1. **Fail closed on entropy.** If the entropy source is unavailable or fails a sanity check, the
   CURVE handshake must return `false`. There is no fallback to `random()`, `micros()`, or
   `analogRead()`. A weak transient key destroys forward secrecy silently.
2. **Never reuse a `(precom key, nonce)` pair.** Session state is created and destroyed with the
   transport. `ZmtpSession::reset()` is mandatory before every handshake, including reconnects.
3. **Outgoing nonce counter starts at 1** and increments once per HELLO, INITIATE and MESSAGE.
   Big-endian.
4. **Enforce incoming nonce monotonicity.** Reject any MESSAGE whose nonce is not strictly greater
   than the last accepted one. Skipping this silently removes replay protection.
5. **Verify the Poly1305 tag on every received frame, including frames being discarded.** The
   `skip` path must still authenticate.
6. **Constant-time tag comparison.** No `memcmp`.
7. **MESSAGE frames are ordinary frames** (outer ZMTP flags `0x00`, or `0x02` when the body
   exceeds 255 bytes). They are *not* command frames. `MORE` lives inside the ciphertext.
   Handshake commands (HELLO/INITIATE) *are* command frames (`0x04`).
8. **The Poly1305 key is keystream bytes 0-31; the ciphertext starts at keystream byte 32.**
   Not at the 64-byte block boundary. Keystream bytes 32-63 -- the second half of block 0 -- are
   reused to encrypt the message's first 32 bytes, and only bytes beyond that come from block 1
   onward. This is the classic NaCl `crypto_secretbox` convention
   (`crypto_box_ZEROBYTES = 32`, `crypto_box_BOXZEROBYTES = 16`) and it is what libzmq v4.3.5
   does: `curve_mechanism_base.cpp` calls libsodium's
   `crypto_box_easy_afternm`/`crypto_box_open_easy_afternm`.
   *Correction, 2026-09-04.* Earlier drafts of this rule said "block 0 is the Poly1305 key,
   ciphertext starts at block 1", which reads as the 64-byte boundary and would misalign every
   frame by 32 bytes against a real broker. That wording came from RFC 8439's
   ChaCha20-Poly1305 construction, where the block-boundary split *is* correct -- it is not
   correct for NaCl's XSalsa20-Poly1305. Confirmed by the NaCl `box.c`/`secretbox.c` vectors,
   which pass only under the byte-32 convention.
9. **No dynamic allocation.** No `new`, no `malloc`, no `String`, no `std::vector`, anywhere in
   the added code. The heap on this board is 8 KB and shared with WiFiS3.
10. **When `MADS_ENABLE_CURVE` is not defined, the produced binary must be byte-comparable to
    today's.** See §2 for what that does and does not mean.

---

## 2. The one design decision: where the opt-in seam goes

The requirement is *"when ECC is not enabled at compile time, the current approach remains
unchanged"*. That means **the build output is unchanged**. It does **not** mean the source is
unchanged, and reading it that way produces the wrong architecture.

### Do NOT do this

Do not sprinkle `#ifdef MADS_ENABLE_CURVE` through the bodies of `mads_agent.cpp` and
`zmtp_codec.cpp`. There are ~40 codec call sites (Appendix B). Conditionalising each one yields
two interleaved implementations of the same protocol in one file, and every future bug has to be
fixed twice.

### Do this instead

Draw the seam at **one** place: the mechanism inside a session object.

* `ZmtpCodec`'s `static` functions become `ZmtpSession`, an object holding `Transport &` plus
  per-connection protocol state. This refactor is **unconditional** -- it happens for everyone.
* With `MADS_ENABLE_CURVE` undefined, `ZmtpSession` has no crypto member, and every method is a
  direct, non-branching equivalent of today's code. Same instructions, same RAM.
* `#ifdef MADS_ENABLE_CURVE` appears in a small, countable number of places:
  1. the `CurveState` member and the mechanism branch inside `zmtp_session.hpp/.cpp`,
  2. `Agent::set_crypto()` and the `_curve_*` members in `mads_agent.hpp/.cpp`,
  3. the `mads/crypto/` translation units' outer guard,
  4. the includes that pull them in.

  Target: **no more than 12 `#ifdef` blocks in the whole library.** If you find yourself writing
  the thirteenth, the seam is in the wrong place -- stop and reconsider.

  *Status after Phase 3: 6 used* (monocypher wrapper, `entropy.hpp`, `entropy_ra4m1.cpp`, and
  three in `entropy_desktop.cpp`). Six remain for Phases 4-6: the `curve.{hpp,cpp}` guard, the
  `z85.{hpp,cpp}` guard, the `ZmtpSession` mechanism branch, and `Agent::set_crypto()` plus its
  members. That is tight but sufficient if the seam stays where §2 puts it. If it is not
  sufficient, that is the signal the seam has drifted -- not a reason to raise the budget.

Breaking the public API is explicitly allowed (adoption is minimal). Prefer a clean API over a
compatible one.

---

## 3. File layout after the change

```
src/
  MadsUnoAgent.h                  (unchanged)
  mads/
    transport.hpp                 (unchanged)
    wifi_transport.hpp            (unchanged)
    toml_scan.{hpp,cpp}           (unchanged)
    zmtp_session.{hpp,cpp}        NEW -- replaces zmtp_codec.{hpp,cpp}
    mads_agent.{hpp,cpp}          modified: call sites + set_crypto()
    curve.{hpp,cpp}               NEW -- CURVE handshake + MESSAGE framing (guarded)
    entropy.hpp                   NEW -- entropy interface (guarded)
    entropy_ra4m1.cpp             NEW -- SCE TRNG backend (guarded + arch guard)
    entropy_desktop.cpp           NEW -- /dev/urandom backend (guarded + arch guard)
    z85.{hpp,cpp}                 NEW -- Z85 decode (guarded)
    crypto/
      monocypher.h                NEW -- vendored, pinned, unmodified
      monocypher.c.inc            NEW -- vendored, pinned, unmodified (see §7.1)
      monocypher_unit.c           NEW -- 4-line guarded wrapper that includes the .inc
      salsa20.{h,cpp}             NEW -- Salsa20 core, HSalsa20, XSalsa20 keystream
      nacl_box.{h,cpp}            NEW -- beforenm, secretbox seal/open, streaming contexts
test/
  desktop/                        NEW -- see Phase 0
examples/
  crypto_pub/                     NEW -- see Phase 6
```

`src/mads/zmtp_codec.*` is deleted, not kept as a shim.

---

## Phase 0 -- Desktop test harness

Nothing else in this plan is verifiable without it. The README claims `mads_agent.cpp` builds on
the desktop against a POSIX-socket stand-in for `WiFiS3.h`; that stand-in is **not in the
repository**. Recreate and commit it.

Build:

```
test/desktop/
  arduino_stub/WiFiS3.h        POSIX WiFiClient stand-in + millis()/micros()/delay()
  Makefile                     g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined
  test_toml_scan.cpp           pure unit tests, no network
  test_zmtp_null.cpp           live test against a real broker, skipped unless MADS_BROKER_HOST set
  README.md                    how to run, and where to point ARDUINOJSON_DIR
```

`WiFiS3.h` must expose exactly the surface `wifi_transport.hpp` uses: `WiFiClient` with
`connect/connected/stop/write/read/available`, plus `WiFi.begin/status/localIP/macAddress` and
`WL_CONNECTED`. Keep it small; it is a test fixture, not an emulator.

The Makefile must also build with `-fstack-usage` and provide a `make stackreport` target that
sums the deepest call chain. You will need it in Phase 7.

**Acceptance.** `make test` passes with ASan/UBSan clean. With a real `mads broker` running and
`MADS_BROKER_HOST` set, `test_zmtp_null` completes a settings fetch and a publish that `mads echo
--jsonl` decodes.

---

## Phase 1 -- `ZmtpCodec` -> `ZmtpSession`, NULL only

No crypto. Pure refactor. This must be provable as a no-op, which is the whole point of doing it
separately.

```cpp
// src/mads/zmtp_session.hpp
namespace Mads {

class ZmtpSession {
public:
  static constexpr uint8_t FLAG_MORE    = 0x01;
  static constexpr uint8_t FLAG_LARGE   = 0x02;
  static constexpr uint8_t FLAG_COMMAND = 0x04;

  explicit ZmtpSession(Transport &t);

  /// Clears all per-connection protocol state. MUST be called before every
  /// handshake, including reconnects.
  void reset();

  bool handshake(const char *socket_type, uint32_t timeout_ms);

  bool send_frame(const uint8_t *data, size_t len, bool more);
  bool send_frame(const char *text, bool more);
  bool send_subscription(const char *topic, bool subscribe);

  /// Reads the next frame's *logical* header. Under CURVE this consumes the
  /// MESSAGE prologue and `len` is the plaintext length, so callers never
  /// see the 33-byte expansion. The session is mid-frame on return: the body
  /// MUST be consumed (recv_frame_body / skip_frame_body / the streaming
  /// trio) before the next call.
  bool recv_frame_header(uint8_t &flags, uint64_t &len, uint32_t timeout_ms);

  bool recv_frame_body(uint8_t *buf, size_t buf_cap, uint64_t len, uint32_t timeout_ms);
  bool skip_frame_body(uint64_t len, uint32_t timeout_ms);

  /// Streaming body read, for bodies too large to buffer (the settings ini
  /// frame). Under CURVE the plaintext is delivered before it is
  /// authenticated, so a caller MUST discard everything it derived from the
  /// chunks if end_recv_body() returns false.
  bool begin_recv_body(uint64_t len);
  int  read_body_chunk(uint8_t *buf, size_t cap, uint32_t timeout_ms);
  bool end_recv_body();

private:
  Transport &_t;
  // ... NULL-mechanism state only, today: none
};

} // namespace Mads
```

Then rewrite `mads_agent.cpp` against it. Two `ZmtpSession` members alongside the two transports,
one local in `fetch_settings()`. Every call site in Appendix B is mechanical except one:

**`fetch_settings()` frame 2** currently bypasses the codec entirely, calling
`settings_transport.read()` into a 32-byte chunk buffer fed to `TomlScan`
(`mads_agent.cpp:200-219`). Convert it to `begin_recv_body` / `read_body_chunk` /
`end_recv_body`, and on a `false` from `end_recv_body()` call `_settings_scan.reset()` and return
`false`. Under NULL, `end_recv_body()` always returns `true`, so behaviour is unchanged -- but the
call must be there now, or Phase 5 will have nowhere to hook the MAC check.

**Acceptance.**
* `git grep -c ZmtpCodec src/` returns nothing.
* `arduino-cli compile` of all three existing examples succeeds, and flash/RAM figures are within
  **±32 bytes** of the pre-refactor build. Record both numbers in the commit message. A larger
  delta means the refactor was not neutral -- find out why before continuing.

  *Measured 2026-09-04 (arduino-cli 1.2.2, `arduino:renesas_uno@1.6.0`, ArduinoJson 7.4.3):*
  `minimal_pub` +32/+8, `uno_r4_sensor` +32/+8, `pub_sub` **+48**/+8 flash/RAM bytes. RAM is
  within budget everywhere (+8 = two `Transport &` references, as expected). `pub_sub` misses the
  flash budget by 16 bytes, traced to the SUB-path call sites plus the mandatory
  `fetch_settings()` trio conversion; accepted rather than reclaimed by member reordering. These
  are the numbers Phase 7's disabled-build check compares against.
* Desktop tests still pass, including the live broker test.

---

## Phase 2 -- Crypto primitives

Everything here is pure computation with published test vectors. No network, no board.

### 2.1 Vendoring Monocypher

Pin an exact release (record the version and commit hash in a header comment). Rename the vendored
`monocypher.c` to `monocypher.c.inc` so the Arduino builder ignores it, and add:

```c
/* src/mads/crypto/monocypher_unit.c */
#ifdef MADS_ENABLE_CURVE
#include "monocypher.c.inc"
#endif
```

This keeps the vendored source byte-identical to upstream *and* makes it provably absent from a
disabled build. Do not edit `monocypher.c.inc` for any reason.

Only `crypto_x25519`, `crypto_x25519_public_key` and `crypto_poly1305*` are used. Everything else
is dropped by `--gc-sections`.

### 2.2 Salsa20 (`crypto/salsa20.{h,cpp}`)

Monocypher does not ship Salsa20 -- its key exchange uses HChaCha20. Write it:

```cpp
void salsa20_core(uint8_t out[64], const uint8_t in[16], const uint8_t key[32]);
void hsalsa20(uint8_t out[32], const uint8_t in[16], const uint8_t key[32]);

struct XSalsa20Keystream {          // XSalsa20 = HSalsa20 subkey + Salsa20 with the 8-byte tail
  void init(const uint8_t key[32], const uint8_t nonce[24]);
  void seek_block(uint64_t block);  // block 0: bytes 0-31 are the Poly1305 key,
                                    // bytes 32-63 are ciphertext keystream (see §1 rule 8)
  void squeeze(uint8_t *out, size_t n);
  void xor_stream(const uint8_t *in, uint8_t *out, size_t n);
};
```

`hsalsa20` differs from `salsa20_core` only in which words it extracts and in not adding the input
back. Get this from the NaCl reference, not from memory.

### 2.3 NaCl box layer (`crypto/nacl_box.{h,cpp}`)

```cpp
/// crypto_box_beforenm: X25519 then HSalsa20 with an all-zero nonce.
bool box_beforenm(uint8_t precom[32], const uint8_t pk[32], const uint8_t sk[32]);

/// One-shot secretbox, output layout tag(16) || ciphertext(n).
void secretbox_seal(uint8_t *out, const uint8_t *pt, size_t n,
                    const uint8_t nonce[24], const uint8_t key[32]);
bool secretbox_open(uint8_t *pt, const uint8_t *in, size_t n_ct,
                    const uint8_t nonce[24], const uint8_t key[32]);

/// Two-pass writer, for encrypting a caller-owned buffer with no copy.
struct SecretboxSeal {
  void init(const uint8_t key[32], const uint8_t nonce[24]);
  void absorb(const uint8_t *pt, size_t n);   // pass 1: keystream + Poly1305, ct discarded
  void tag(uint8_t out[16]);                  // finalise pass 1
  void restart();                             // rewind keystream to byte 32 (see §1 rule 8)
  void encrypt(const uint8_t *pt, uint8_t *ct, size_t n);  // pass 2
};

/// Streaming reader, for bodies larger than RAM.
struct SecretboxOpen {
  void init(const uint8_t key[32], const uint8_t nonce[24], const uint8_t tag[16]);
  void update(const uint8_t *ct, uint8_t *pt, size_t n);
  bool finish();                              // constant-time compare
};
```

`box_beforenm` must reject an all-zero X25519 output (a small-order peer key).

### 2.4 Tests

Add `test/desktop/test_crypto_vectors.cpp`. Sources for vectors (fetch them, do not invent them):

| primitive | source |
|---|---|
| Salsa20 core | NaCl `tests/core1.c`, `core2.c` |
| HSalsa20 | NaCl `tests/core3.c`, `core4.c`; libsodium `test/default/core3.c` |
| XSalsa20 | NaCl `tests/stream.c` |
| Poly1305 | RFC 8439 §2.5.2 |
| X25519 | RFC 7748 §5.2 and §6.1 |
| crypto_box / secretbox | NaCl `tests/box.c`, `secretbox.c` |

Also add a differential test: `SecretboxSeal` (two-pass) and `secretbox_seal` (one-shot) must
produce identical output for random lengths 0..4096, and `SecretboxOpen` must round-trip both and
reject every single-bit flip in tag and ciphertext.

**Acceptance.** All published vectors pass. Differential and round-trip tests pass under ASan and
UBSan. Coverage over `crypto/` is not the goal -- exact vector agreement is.

---

## Phase 3 -- Entropy

```cpp
// src/mads/entropy.hpp   (inside #ifdef MADS_ENABLE_CURVE)
namespace Mads {
  /// One-time bring-up. Returns false if no usable source exists.
  bool entropy_init();
  /// Returns false if the source failed. Callers MUST fail closed.
  bool entropy_fill(uint8_t *out, size_t n);
}
```

### 3.1 Board backend (`entropy_ra4m1.cpp`)

The RA4M1's SCE TRNG is already linked into every UNO R4 sketch:
`variants/UNOWIFIR4/libs/libfsp.a` in `arduino/ArduinoCore-renesas` defines
`HW_SCE_McuSpecificInit` and `HW_SCE_GenerateRandomNumberSub` (member `hw_sce_p09.o`). FSP's
`r_sce.h` is not shipped with the core, so declare them yourself:

```cpp
extern "C" {
  void HW_SCE_McuSpecificInit(void);
  /* returns FSP_SUCCESS (0) on success; writes 4 words = 16 bytes */
  uint32_t HW_SCE_GenerateRandomNumberSub(uint32_t *out);
}
```

`entropy_init()` calls `HW_SCE_McuSpecificInit()` once, then draws 64 bytes and applies a crude
health check: not all-zero, not all-`0xFF`, and no 16-byte block equal to the previous one. Cache
the result; return it from every subsequent call.

This is **[Likely, unverified on hardware]**. It is the Phase 8 gate. Until then, guard the file
so it compiles but is never the desktop path.

### 3.2 Desktop backend (`entropy_desktop.cpp`)

`/dev/urandom`. Plus a test hook -- when `MADS_CURVE_TEST_ENTROPY` is defined, `entropy_fill`
returns bytes from an injectable deterministic stream, so handshake output becomes reproducible and
byte-comparable in tests. The hook must be impossible to enable in a board build: `#error` if
`MADS_CURVE_TEST_ENTROPY` is defined and `ARDUINO` is too.

**Acceptance.** Desktop backend passes a smoke test. Board backend compiles under
`arduino-cli compile`. The test hook produces identical bytes across runs.

---

## Phase 4 -- CURVE handshake

`src/mads/curve.{hpp,cpp}`, all inside `#ifdef MADS_ENABLE_CURVE`.

```cpp
struct CurveKeys {           // raw, already Z85-decoded
  uint8_t client_public[32];
  uint8_t client_secret[32];
  uint8_t server_public[32];
};

struct CurveState {
  uint8_t  precom[32];       // beforenm(S', c') -- the MESSAGE key
  uint64_t nonce_out;        // starts at 1
  uint64_t nonce_in;         // last accepted peer nonce
  bool     ready;
};

/// Runs greeting + HELLO/WELCOME/INITIATE/READY. On success `st` is armed
/// for MESSAGE framing. All working buffers are static (see §7.2).
bool curve_handshake(Transport &t, const CurveKeys &k, const char *socket_type,
                     uint32_t timeout_ms, CurveState &st);
```

Order of operations, with the four X25519 scalar multiplications marked:

1. Send greeting with mechanism `CURVE`, `as-server = 0`, **`minor = 0`** (keeps the
   single-byte-prefixed SUBSCRIBE encoding -- `zmtp_engine.cpp:390`, `handshake_v3_0()` passes
   `downgrade_sub = true`).
2. Receive and validate the peer greeting; require `revision == 3` and mechanism `CURVE`.
3. `entropy_fill(c', 32)`; clamp; `crypto_x25519_public_key(C', c')`. **[mult 1]**
4. `box_beforenm(k_Sc, S, c')`. **[mult 2]** Cache this -- it serves both the HELLO box and the
   WELCOME open. Computing it twice is a wasted ~100 ms.
5. Send HELLO (Appendix A.2), nonce 1.
6. Receive WELCOME, require body exactly 168 bytes, open with `k_Sc`. Extract `S'` and the
   96-byte cookie.
7. `box_beforenm(st.precom, S', c')`. **[mult 3]**
8. `entropy_fill(vouch_nonce_tail, 16)`; build and seal the vouch box to `S'` from `c`.
   **[mult 4]**
9. Send INITIATE (Appendix A.4), nonce 2. Metadata is the same `Socket-Type` property
   `send_ready()` builds today -- reuse that code, do not rewrite it.
10. Receive the reply. If it is `\x05ERROR`, read the 1-byte reason length and the reason, and
    surface it (see §4.1). If it is `\x05READY`, open it with `st.precom`, set
    `st.nonce_in` from its nonce, discard the metadata, set `st.ready = true`.

Any failure: zeroise `c'`, `k_Sc` and `st`, return `false`.

### 4.1 Error reporting

A CURVE failure is otherwise indistinguishable from a dropped connection, which makes field
debugging miserable. Add:

```cpp
enum class CurveError : uint8_t {
  none, no_entropy, greeting, welcome, mac, rejected, timeout, protocol
};
CurveError Agent::last_curve_error() const;
```

When the broker sends `ERROR`, that is `rejected` -- almost always "this board's `.pub` is not in
the broker's keys dir, or the broker was not restarted after adding it". Say so in the docs.

### 4.2 Tests

`test/desktop/test_curve_handshake.cpp`:
* With `MADS_CURVE_TEST_ENTROPY` pinned, assert the produced HELLO and INITIATE match recorded
  golden byte strings. Generate the goldens **once**, from a run verified against a real
  `mads broker --crypto`, and commit them. This is the regression net for every later change.
* Live test against a real `mads broker --crypto` (skipped unless `MADS_BROKER_HOST` and key paths
  are set): full handshake on all three sockets.
* Negative: wrong `broker_public` -> WELCOME open fails, `CurveError::mac`. Unknown client key ->
  `CurveError::rejected`.

**Acceptance.** Golden vectors stable. Against a real `--crypto` broker with
`[broker] auth_verbose = true`, the ZAP log shows `granted` for all three connections.

---

## Phase 5 -- MESSAGE framing

This is where `ZmtpSession`'s methods gain their CURVE branch. Layout: Appendix A.6.

### Send

**No public API change.** `send_frame(data, len, more)` already receives a stable, re-readable
`const uint8_t *`, which is exactly what the two-pass encryption needs:

1. Write the outer ZMTP header for `len + 33` (`FLAG_LARGE` if that exceeds 255; note the
   threshold is on the *expanded* length).
2. `SecretboxSeal::init` with `"CurveZMQMESSAGEC" || nonce_out`.
3. Pass 1: `absorb(flags_byte)` then `absorb(data, len)`; `tag()`.
4. Write `"\x07MESSAGE"`, the 8-byte nonce, the 16-byte tag.
5. `restart()`; `encrypt` the flags byte, then `data` in fixed-size chunks (use 64 bytes; do not
   allocate).
6. `++nonce_out`.

For small frames (say `len <= 192`) take a one-shot path through a single static scratch buffer --
it halves the Salsa20 work on the common case, which is every JSON publish. The two-pass path
exists for the blob overload.

`send_subscription()` needs **no special handling**: it already emits `[0x01][topic]` as an
ordinary frame body, and that is precisely what the broker's downgraded decoder expects to find
inside the ciphertext.

### Receive

`recv_frame_header()` under CURVE:
1. Read the outer ZMTP header. Require `!(flags & FLAG_COMMAND)`.
2. Read 8 bytes, require `"\x07MESSAGE"`. Read the 8-byte nonce; require strictly greater than
   `st.nonce_in`; store it.
3. Read the 16-byte tag.
4. `SecretboxOpen::init`. Read 1 ciphertext byte, `update` it to get the logical flags byte.
5. Report `flags` = that byte masked to `MORE|COMMAND`, and `len` = wire body length − 33.

`recv_frame_body`, `skip_frame_body` and the streaming trio then all run on the same
`SecretboxOpen` and must call `finish()`. **`skip_frame_body` authenticates too** -- it discards
plaintext, it does not skip the MAC.

`fetch_settings()`'s ini frame is the streaming case: chunks go to `TomlScan` before
authentication, so on `end_recv_body() == false` the scanner must be `reset()` and the fetch must
fail. That is safe -- `TomlScan` has no side effects outside itself -- but it must be explicit.

`poll()`'s receive buffer: the plaintext is `flags_byte || payload`, so either give the decrypt one
spare byte or `memmove` the payload down by one. Either is fine; pick one and comment it.

### Tests

* Round-trip every `ZmtpSession` send path through a matching receive path in-process.
* Tamper tests: flip one bit in tag, in ciphertext, and in the nonce -> all rejected.
* Replay: re-feed a valid frame -> rejected on the nonce check.
* Live: publish JSON and a 1000-byte blob (the `FLAG_LARGE` path) to a real `--crypto` broker and
  decode with `mads echo --jsonl`. Subscribe and receive from `mads feedback`.

**Acceptance.** All of the above. Blob publish RAM must not scale with blob size -- prove it by
publishing a 16 KB blob on the desktop build under a heap/stack watermark check.

---

## Phase 6 -- Agent API, secrets, examples

```cpp
#ifdef MADS_ENABLE_CURVE
  /// Arms CURVE for every connection this agent opens. Call before begin().
  /// Keys are the 40-character Z85 strings written by `mads --keypair=<name>`.
  /// Returns false if any key fails to decode.
  bool set_crypto(const char *client_public_z85,
                  const char *client_secret_z85,
                  const char *broker_public_z85);
  CurveError last_curve_error() const;
#endif
```

Chosen over an extra `begin()` overload because the reconnect path needs the keys to outlive the
call, and because it keeps `begin()`'s signature identical in both build modes.

`ensure_pub_link()`, `ensure_sub_link()` and `fetch_settings()` each call `session.reset()` then
`session.handshake(...)`; the session picks NULL or CURVE from whether `set_crypto()` succeeded.

`z85_decode(const char *in40, uint8_t out[32])`: strict. Reject any length but 40, and any
character outside the Z85 alphabet. ~25 lines.

New example `examples/crypto_pub/`:

```
crypto_pub.ino
build_opt.h                  ->  -DMADS_ENABLE_CURVE
arduino_secrets.h.example    ->  SSID/PASS/BROKER_HOST plus
                                 SECRET_CURVE_CLIENT_PUBLIC / _SECRET / SECRET_CURVE_BROKER_PUBLIC
```

The sketch must print `last_curve_error()` on failure -- it is the only diagnostic a user gets.

**Acceptance.** `examples/crypto_pub` compiles with `MADS_ENABLE_CURVE`, and the three existing
examples compile without it. `arduino_secrets.h` stays gitignored (it already is).

---

## Phase 7 -- Build gating and footprint proof

### 7.1 Enabling the feature

A `#define` in the `.ino` will not reach library translation units. Two mechanisms:

* `arduino-cli compile --build-property "compiler.cpp.extra_flags=-DMADS_ENABLE_CURVE"`.
  **Verified working** with arduino-cli 1.2.2 and `arduino:renesas_uno@1.6.0`. Note it
  *replaces* rather than appends to `compiler.cpp.extra_flags`; say so in the README.
* `build_opt.h` in the sketch folder containing `-DMADS_ENABLE_CURVE`.
  **Did not work** on that same arduino-cli 1.2.2 / core 1.6.0 combination -- the sketch never
  saw the macro. Not tested across other versions, so this is a data point rather than proof it
  never works. Phase 6 must re-check it on the actual target setup before documenting it as
  supported, and must not ship `examples/crypto_pub/build_opt.h` as the only enable path.

### 7.2 Stack

**This is the constraint that most likely bites, and it is not obvious.**
`variants/UNOWIFIR4/includes/ra_cfg/fsp_cfg/bsp/bsp_cfg.h` sets
`BSP_CFG_STACK_MAIN_BYTES = 0x400` -- **1 KB of reserved main stack** -- and `setup()`/`loop()` run
on it (`cores/arduino/main.cpp` calls them directly from `arduino_main()`). Worse,
`main.cpp` disables the stack-pointer monitor (`R_MPU_SPMON->SP[0].CTL = 0`), so an overflow does
not fault -- it silently corrupts whatever lies below.

In practice the usable stack is bounded by the gap between `__StackTop` and the top of the 8 KB
heap rather than by the reserved 0x400, so more than 1 KB often works. Do not rely on that.

Rules:
* Every CURVE working buffer -- HELLO (200 B), INITIATE (~300 B), WELCOME (168 B), the transient
  keypair, `k_Sc`, the cookie -- is a **file-static** buffer inside `#ifdef MADS_ENABLE_CURVE`,
  not a local. Disabled builds pay nothing for them.
* Reuse one static scratch buffer across HELLO/WELCOME/INITIATE; they do not overlap in time.
* Run `make stackreport` (Phase 0) and record the deepest chain through `curve_handshake`. If it
  exceeds **512 bytes**, hoist more state to statics until it does not.
* This is also why Monocypher and not TweetNaCl: TweetNaCl's `crypto_scalarmult` puts
  `i64 x[80]` (640 B) and six 128-byte `gf` locals in one frame -- roughly 1.4 KB, which does not
  fit here at all.

### 7.3 Footprint

Record, in the commit message, for `examples/uno_r4_sensor` (disabled) and `examples/crypto_pub`
(enabled): flash bytes, global RAM bytes, and the delta. Baseline today is ~70 KB flash / ~8.8 KB
RAM. Expected: **+10-13 KB flash, +~300 B RAM when enabled; 0/0 when disabled.**

**Acceptance.** The disabled build's flash and RAM match the Phase 1 numbers **exactly**. Not
"close" -- exactly. Any difference means crypto code leaked into the disabled path; find it.

---

## Phase 8 -- Hardware bring-up (human, on a real board)

Prepare a checklist and a diagnostic sketch; do not claim any of this as done.

1. **TRNG gate.** Flash a sketch that calls `entropy_init()` and dumps 4 KB over Serial. Check:
   not constant, no repeated 16-byte blocks, and different across power cycles. **If this fails,
   everything downstream is insecure -- stop and fall back to the hedged DRBG in CURVE.md §5.**
2. Stack high-water: paint the stack region at boot, run a full `begin()`, report the watermark.
3. Time one `crypto_x25519` with `micros()`. Report it. Then time a full `begin()`.
4. End-to-end against a real `mads broker --crypto` with `auth_verbose = true`: settings fetch,
   publish, subscribe, and a broker restart mid-run to exercise reconnect.
5. Confirm reconnect does not reuse nonces: log `nonce_out` at handshake completion; it must be 3
   on every fresh link.

---

## Phase 9 -- Documentation

* README: move CURVE out of the "not supported" list into a supported-but-opt-in section; document
  `build_opt.h`, `set_crypto()`, the key-deployment procedure (generate on PC with
  `mads --keypair`, copy the `.pub` to the broker's keys dir, **restart the broker**), the
  `[broker] ip_whitelist` interaction with DHCP, and `auth_verbose` as the debugging lever.
* README "Status": update with real measured figures from Phase 8, and state plainly what was and
  was not exercised on hardware.
* CURVE.md: add a short header noting which parts the implementation confirmed or contradicted.
  Leave the study otherwise intact -- it is the reasoning record.
* Security note, verbatim in the README: the private key lives in plaintext sketch flash on a board
  with an open bootloader. CURVE protects against a network attacker, not against someone holding
  the board. Forward secrecy means a stolen permanent key does not decrypt past traffic -- but only
  if the TRNG in step 1 is genuine.

---

## Appendix A -- Wire layouts

All from libzmq v4.3.5. Short nonces are big-endian `uint64`.

### A.1 Greeting (64 bytes, unchanged except the mechanism field)

| offset | len | value |
|---|---|---|
| 0 | 1 | `0xFF` |
| 1 | 8 | zeros |
| 9 | 1 | `0x7F` |
| 10 | 1 | `3` (revision) |
| 11 | 1 | `0` (minor -- keep at 0) |
| 12 | 16 | `"CURVE"` zero-padded |
| 32 | 1 | `0` (as-server) |
| 33 | 31 | zeros |

### A.2 HELLO -- command frame (`0x04`), body 200 bytes

| offset | len | content |
|---|---|---|
| 0 | 6 | `\x05HELLO` |
| 6 | 2 | `\x01\x00` |
| 8 | 72 | zeros |
| 80 | 32 | `C'` |
| 112 | 8 | short nonce (1) |
| 120 | 80 | `secretbox(64 zero bytes)` under `"CurveZMQHELLO---"‖nonce`, key `beforenm(S, c')` |

### A.3 WELCOME -- command frame, body exactly 168 bytes

| offset | len | content |
|---|---|---|
| 0 | 8 | `\x07WELCOME` |
| 8 | 16 | long nonce |
| 24 | 144 | box under `"WELCOME-"‖long`, key `beforenm(S, c')`; plaintext = `S'`(32) ‖ cookie(96) |

### A.4 INITIATE -- command frame, body `113 + 128 + 16 + len(metadata)`

| offset | len | content |
|---|---|---|
| 0 | 9 | `\x08INITIATE` |
| 9 | 96 | cookie, echoed verbatim |
| 105 | 8 | short nonce (2) |
| 113 | 144+md | box under `"CurveZMQINITIATE"‖nonce`, key `beforenm(S', c')` |

INITIATE plaintext: `C`(32) ‖ vouch nonce tail(16) ‖ vouch box(80) ‖ metadata.
Vouch box: `secretbox(C' ‖ S)` under `"VOUCH---"‖16 random`, key `beforenm(S', c)`.

### A.5 READY / ERROR -- command frames

`\x05READY` (6) ‖ short nonce (8) ‖ box under `"CurveZMQREADY---"‖nonce`, key `precom`.
`\x05ERROR` (6) ‖ reason length (1) ‖ reason.

### A.6 MESSAGE -- **ordinary** frame (`0x00`, or `0x02` if body > 255)

```
"\x07MESSAGE"(8) ‖ short nonce(8) ‖ Poly1305 tag(16) ‖ XSalsa20(flags_byte ‖ payload)
```

Nonce prefix `"CurveZMQMESSAGEC"` board→broker, `"CurveZMQMESSAGES"` broker→board.
`flags_byte` = `MORE`(0x01) | `COMMAND`(0x04). Overhead: flat **33 bytes**.

---

## Appendix B -- Call-site inventory (`src/mads/mads_agent.cpp`, pre-refactor line numbers)

| lines | site | note |
|---|---|---|
| 34, 102 | `handshake_null(_pub_transport, "PUB")` | mechanical |
| 128, 251 | `handshake_null(_sub_transport, "SUB")` | mechanical |
| 155 | `handshake_null(settings_transport, "REQ")` | mechanical |
| 136, 256, 286 | `send_subscription` | mechanical; body unchanged under CURVE |
| 164-167 | REQ request frames | mechanical |
| 178-189 | reply frames 0-1, header+skip | mechanical |
| 200-219 | **reply frame 2, raw `transport.read()` loop into `TomlScan`** | **the one real conversion** -- streaming trio, must handle `end_recv_body()` failure |
| 224-227 | trailing frame drain | mechanical |
| 303-307 | `publish()` 3-frame JSON | mechanical; small-frame fast path applies |
| 357-363 | blob `publish()` 3 frames | **two-pass path**; must not buffer the blob |
| 404-444 | `poll()` receive | mechanical + the 1-byte plaintext offset |

---

## Appendix C -- Pitfalls, ranked by how much time they will cost

1. **The Poly1305 key is keystream bytes 0-31; ciphertext starts at keystream byte 32**, inside
   block 0, not at block 1. See §1 rule 8 -- including why the natural-sounding
   "block 0 / block 1" phrasing is the ChaCha20-Poly1305 rule and wrong here. A 32-byte
   misalignment produces a handshake that fails with no useful signal.
2. **MESSAGE is an ordinary frame, not a command frame.** libzmq's `pull_and_encode()` never sets
   `msg_t::command`. Setting `0x04` on the outer frame makes the broker treat it as a handshake
   command and drop the connection.
3. **Computing `beforenm(S, c')` twice.** Correct, but wastes ~100 ms per connection.
4. **Forgetting to authenticate skipped frames.** No symptom at all until someone attacks you.
5. **`FLAG_LARGE` threshold is on the expanded length** (`len + 33`), not the plaintext length. A
   223-byte payload crosses 255 after expansion.
6. **Reusing session state across a reconnect.** `reset()` before every handshake, no exceptions.
7. **Stack.** See §7.2. Silent corruption, not a crash.
8. **`memcmp` on the tag.** Use a constant-time compare.
