#pragma once
// Salsa20 / HSalsa20 / XSalsa20, guarded by MADS_ENABLE_CURVE by the one
// translation unit that compiles this (salsa20.cpp is only ever built when
// the caller defines MADS_ENABLE_CURVE -- see DEVELOPER.md).
//
// Monocypher does not ship Salsa20 (its own key exchange uses HChaCha20),
// so this is written from scratch against the NaCl reference
// (tweetnacl.c's unified core()/crypto_stream_salsa20_xor(), fetched from
// https://tweetnacl.cr.yp.to/20140427/tweetnacl.c per DEVELOPER.md Sec
// 2.2's instruction to work from the NaCl reference, not memory) and
// cross-checked against the published NaCl/libsodium test vectors in
// test/desktop/test_crypto_vectors.cpp.
#include <cstddef>
#include <cstdint>

namespace Mads {

/// Raw Salsa20 core: the 20-round permutation of (constants, key, in), with
/// the original input added back word-for-word -- the standard 64-byte
/// Salsa20 block function. `in` supplies the 16 bytes placed at state words
/// 6..9; a keystream generator packs an 8-byte nonce tail plus an 8-byte
/// little-endian block counter into it (see XSalsa20Keystream below).
void salsa20_core(uint8_t out[64], const uint8_t in[16], const uint8_t key[32]);

/// HSalsa20: the same 20-round permutation, but the output is the raw
/// permuted words at state positions {0,5,10,15,6,7,8,9} with NO input
/// feedforward (unlike salsa20_core) -- this is what makes it safe to use
/// as a nonce-extension/subkey-derivation primitive rather than a stream
/// cipher block. Used by crypto_box_beforenm (HSalsa20 with an all-zero
/// 16-byte input) and by XSalsa20's own subkey derivation (HSalsa20 with
/// the first 16 bytes of the 24-byte XSalsa20 nonce).
void hsalsa20(uint8_t out[32], const uint8_t in[16], const uint8_t key[32]);

/// XSalsa20 keystream generator: HSalsa20(key, nonce[0:16]) yields a
/// 32-byte subkey, then plain Salsa20 runs with that subkey and
/// nonce[16:24] as its 8-byte tail, block counter starting at 0
/// (little-endian, per-64-byte-block). This is exactly NaCl's
/// crypto_stream/crypto_stream_xor construction, generalised to allow
/// seeking to an arbitrary block index instead of only sequential output --
/// crypto/nacl_box.cpp needs that to reuse block 0's keystream for both the
/// Poly1305 key (its first 32 bytes) and the first 32 ciphertext bytes (its
/// second 32 bytes), matching libzmq v4.3.5's crypto_box_afternm framing
/// (see nacl_box.cpp's file comment for why -- DEVELOPER.md's "block 0 is
/// the Poly1305 key, ciphertext starts at block 1" undersells this: it is
/// byte 32, not the 64-byte block-1 boundary).
struct XSalsa20Keystream {
  void init(const uint8_t key[32], const uint8_t nonce[24]);

  /// Positions the generator so the next squeeze()/xor_stream() call
  /// produces keystream bytes starting at byte offset block*64. Discards
  /// any partially-consumed cached block.
  void seek_block(uint64_t block);

  /// Writes n bytes of keystream to out, advancing the position by n (n
  /// need not be a multiple of 64 -- a partially-consumed block is cached
  /// across calls).
  void squeeze(uint8_t *out, size_t n);

  /// XORs n bytes of `in` with n bytes of keystream into `out` (in/out may
  /// alias -- encrypts/decrypts in place), advancing the position by n.
  void xor_stream(const uint8_t *in, uint8_t *out, size_t n);

private:
  uint8_t _subkey[32];
  uint8_t _nonce_tail[8];
  uint8_t _block[64];
  size_t _block_pos = 64; // 64 == no cached bytes left in _block
  uint64_t _block_index = 0;

  void refill();
};

} // namespace Mads
