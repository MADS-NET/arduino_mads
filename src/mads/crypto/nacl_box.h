#pragma once
// The NaCl "box"/"secretbox" layer used by CurveZMQ: X25519 + HSalsa20 key
// agreement (box_beforenm) and XSalsa20-Poly1305 authenticated encryption
// (secretbox_*). Guarded the same way as salsa20.{h,cpp} -- only compiled
// when MADS_ENABLE_CURVE is defined.
//
// Wire framing note (read before touching any of this): the Poly1305 key
// and the message ciphertext share Salsa20 keystream block 0, split at
// BYTE 32 -- keystream[0:32] is the Poly1305 one-time key, keystream[32:64]
// is reused as the first 32 bytes of ciphertext, and only ciphertext bytes
// beyond that come from block 1 onward. This is the classic NaCl
// crypto_secretbox convention (crypto_box_ZEROBYTES=32 /
// crypto_box_BOXZEROBYTES=16), and it is what libzmq v4.3.5 actually does
// -- curve_mechanism_base.cpp's encode()/decode() call libsodium's
// crypto_box_easy_afternm()/crypto_box_open_easy_afternm(), i.e. exactly
// this construction (verified against
// https://github.com/zeromq/libzmq/blob/v4.3.5/src/curve_mechanism_base.cpp
// lines ~130-250, since this is the one thing CURVE_PLAN.md warns is the
// most likely bug and its own prose ("block 0 is the Poly1305 key,
// ciphertext starts at block 1") reads as the 64-byte block boundary, which
// would be a 32-byte misalignment against the real wire protocol -- see the
// note passed back to the plan's author). All four functions/structs below
// implement the byte-32 convention; none of them expose that detail to
// callers.
#include "monocypher.h"
#include "salsa20.h"
#include <cstddef>
#include <cstdint>

namespace Mads {

/// crypto_box_beforenm: X25519(sk, pk) then HSalsa20 with an all-zero
/// 16-byte input, i.e. the standard CurveZMQ/NaCl "precompute the shared
/// key" step. Returns false (and does not touch `precom`) if the X25519
/// output is all-zero -- a small-order/invalid peer public key.
bool box_beforenm(uint8_t precom[32], const uint8_t pk[32], const uint8_t sk[32]);

/// One-shot secretbox seal. Output layout: tag(16) || ciphertext(n) --
/// exactly the wire's MESSAGE/HELLO/WELCOME/INITIATE/READY box layout
/// (Appendix A), with none of NaCl's zero-padding bytes. `out` must have
/// room for 16 + n bytes; `pt` and `out + 16` may alias (in-place seal).
void secretbox_seal(uint8_t *out, const uint8_t *pt, size_t n,
                    const uint8_t nonce[24], const uint8_t key[32]);

/// One-shot secretbox open. `in` is tag(16) || ciphertext(n_ct) as produced
/// by secretbox_seal. Returns false (and does not touch `pt`) if the tag
/// does not verify -- constant-time comparison (Monocypher's
/// crypto_verify16), never memcmp. `pt` and `in + 16` may alias.
bool secretbox_open(uint8_t *pt, const uint8_t *in, size_t n_ct,
                    const uint8_t nonce[24], const uint8_t key[32]);

/// Two-pass writer: encrypts a caller-owned buffer with no extra copy of
/// the plaintext or ciphertext (CURVE_PLAN.md Sec 5's blob publish path).
/// Usage: init(); absorb(flags_byte,1); absorb(data,len); tag(mac); then
/// either send the frame header+mac now and stream the ciphertext with
/// restart()+encrypt(), or call encrypt() directly for a buffered send.
struct SecretboxSeal {
  void init(const uint8_t key[32], const uint8_t nonce[24]);
  /// Pass 1: generates the keystream and feeds the resulting ciphertext
  /// into Poly1305, discarding the ciphertext bytes themselves. May be
  /// called multiple times (e.g. once for a 1-byte flags prefix, once for
  /// the payload) before tag().
  void absorb(const uint8_t *pt, size_t n);
  /// Finalises pass 1 and writes the 16-byte tag. absorb() must not be
  /// called again after this without an intervening init().
  void tag(uint8_t out[16]);
  /// Rewinds the keystream to the start of the message content (i.e. back
  /// to logical byte 0 of pass 1 -- NOT byte 0 of the Salsa20 block stream,
  /// see the file comment) so pass 2 reproduces the identical ciphertext
  /// absorb() computed. Call once, after tag(), before the first encrypt().
  void restart();
  /// Pass 2: `pt`/`ct` may alias. Must be called with the exact same byte
  /// sequence, in the exact same chunking-independent total, as the
  /// absorb() calls that preceded tag() (chunk sizes themselves may
  /// differ -- only the concatenated bytes must match).
  void encrypt(const uint8_t *pt, uint8_t *ct, size_t n);

private:
  XSalsa20Keystream _ks;
  crypto_poly1305_ctx _poly;
  uint8_t _first32[32]; // block 0's second half, cached for the encrypt() pass
  size_t _pos = 0;       // logical position within the message (post block-0 split)

  void xor_next(const uint8_t *pt, uint8_t *ct, size_t n);
};

/// Streaming reader, for bodies larger than RAM (the settings ini frame's
/// CURVE counterpart, and blob receive). Plaintext is delivered by
/// update() *before* it is authenticated -- finish()'s constant-time
/// compare is the only thing that proves it was genuine. A caller that
/// acted on the plaintext before calling finish() (e.g. fed it to a
/// parser) MUST discard everything derived from it if finish() returns
/// false (see ZmtpSession::begin_recv_body's doc comment -- this is
/// exactly the mechanism that hook exists for).
struct SecretboxOpen {
  void init(const uint8_t key[32], const uint8_t nonce[24], const uint8_t tag[16]);
  /// `ct`/`pt` may alias. Total bytes across all update() calls for one
  /// message must equal the sender's plaintext length exactly.
  void update(const uint8_t *ct, uint8_t *pt, size_t n);
  /// Constant-time comparison of the accumulated Poly1305 result against
  /// the tag passed to init(). Must be called exactly once, after every
  /// update() call for the message.
  bool finish();

private:
  XSalsa20Keystream _ks;
  crypto_poly1305_ctx _poly;
  uint8_t _expected_tag[16];
  uint8_t _first32[32];
  size_t _pos = 0;

  void xor_next(const uint8_t *ct, uint8_t *pt, size_t n);
};

} // namespace Mads
