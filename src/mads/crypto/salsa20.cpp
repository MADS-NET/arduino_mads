#include "salsa20.h"
#include <cstring>

namespace Mads {

namespace {

inline uint32_t rotl32(uint32_t x, int c) {
  return (x << c) | (x >> (32 - c));
}

inline uint32_t load32_le(const uint8_t *x) {
  return static_cast<uint32_t>(x[0]) | (static_cast<uint32_t>(x[1]) << 8) |
         (static_cast<uint32_t>(x[2]) << 16) |
         (static_cast<uint32_t>(x[3]) << 24);
}

inline void store32_le(uint8_t *x, uint32_t u) {
  x[0] = static_cast<uint8_t>(u);
  x[1] = static_cast<uint8_t>(u >> 8);
  x[2] = static_cast<uint8_t>(u >> 16);
  x[3] = static_cast<uint8_t>(u >> 24);
}

const uint8_t sigma[16] = {'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
                            '2', '-', 'b', 'y', 't', 'e', ' ', 'k'};

// The unified Salsa20/HSalsa20 permutation core, translated word-for-word
// from tweetnacl.c's static core() (fetched from
// https://tweetnacl.cr.yp.to/20140427/tweetnacl.c) -- see salsa20.h's
// comment for why this is transcribed rather than reconstructed from
// memory. `hsalsa` selects HSalsa20's raw-extract, no-feedforward output
// instead of Salsa20's standard block-with-feedforward output.
void core(uint8_t *out, const uint8_t in[16], const uint8_t key[32],
          const uint8_t c[16], bool hsalsa) {
  uint32_t w[16], x[16], y[16], t[4];

  for (int i = 0; i < 4; ++i) {
    x[5 * i] = load32_le(c + 4 * i);
    x[1 + i] = load32_le(key + 4 * i);
    x[6 + i] = load32_le(in + 4 * i);
    x[11 + i] = load32_le(key + 16 + 4 * i);
  }

  for (int i = 0; i < 16; ++i)
    y[i] = x[i];

  for (int round = 0; round < 20; ++round) {
    for (int j = 0; j < 4; ++j) {
      for (int m = 0; m < 4; ++m)
        t[m] = x[(5 * j + 4 * m) % 16];
      t[1] ^= rotl32(t[0] + t[3], 7);
      t[2] ^= rotl32(t[1] + t[0], 9);
      t[3] ^= rotl32(t[2] + t[1], 13);
      t[0] ^= rotl32(t[3] + t[2], 18);
      for (int m = 0; m < 4; ++m)
        w[4 * j + (j + m) % 4] = t[m];
    }
    for (int m = 0; m < 16; ++m)
      x[m] = w[m];
  }

  if (hsalsa) {
    for (int i = 0; i < 16; ++i)
      x[i] += y[i];
    for (int i = 0; i < 4; ++i) {
      x[5 * i] -= load32_le(c + 4 * i);
      x[6 + i] -= load32_le(in + 4 * i);
    }
    for (int i = 0; i < 4; ++i) {
      store32_le(out + 4 * i, x[5 * i]);
      store32_le(out + 16 + 4 * i, x[6 + i]);
    }
  } else {
    for (int i = 0; i < 16; ++i)
      store32_le(out + 4 * i, x[i] + y[i]);
  }
}

} // namespace

void salsa20_core(uint8_t out[64], const uint8_t in[16], const uint8_t key[32]) {
  core(out, in, key, sigma, false);
}

void hsalsa20(uint8_t out[32], const uint8_t in[16], const uint8_t key[32]) {
  core(out, in, key, sigma, true);
}

void XSalsa20Keystream::init(const uint8_t key[32], const uint8_t nonce[24]) {
  hsalsa20(_subkey, nonce, key);
  memcpy(_nonce_tail, nonce + 16, 8);
  _block_pos = 64;
  _block_index = 0;
}

void XSalsa20Keystream::seek_block(uint64_t block) {
  _block_index = block;
  _block_pos = 64; // force refill() on next squeeze/xor_stream
}

void XSalsa20Keystream::refill() {
  uint8_t in16[16];
  memcpy(in16, _nonce_tail, 8);
  // Block counter: 8-byte little-endian, per NaCl's crypto_stream_salsa20_xor.
  uint64_t ctr = _block_index;
  for (int i = 0; i < 8; ++i) {
    in16[8 + i] = static_cast<uint8_t>(ctr & 0xFF);
    ctr >>= 8;
  }
  salsa20_core(_block, in16, _subkey);
  ++_block_index;
  _block_pos = 0;
}

void XSalsa20Keystream::squeeze(uint8_t *out, size_t n) {
  size_t done = 0;
  while (done < n) {
    if (_block_pos == 64)
      refill();
    size_t avail = 64 - _block_pos;
    size_t take = (n - done) < avail ? (n - done) : avail;
    memcpy(out + done, _block + _block_pos, take);
    _block_pos += take;
    done += take;
  }
}

void XSalsa20Keystream::xor_stream(const uint8_t *in, uint8_t *out, size_t n) {
  size_t done = 0;
  while (done < n) {
    if (_block_pos == 64)
      refill();
    size_t avail = 64 - _block_pos;
    size_t take = (n - done) < avail ? (n - done) : avail;
    for (size_t i = 0; i < take; ++i)
      out[done + i] = in[done + i] ^ _block[_block_pos + i];
    _block_pos += take;
    done += take;
  }
}

} // namespace Mads
