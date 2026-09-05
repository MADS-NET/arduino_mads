#include "nacl_box.h"
#include <cstring>

namespace Mads {

namespace {

// Consumes keystream block 0 in full (64 bytes) and splits it: the first 32
// bytes are the Poly1305 one-time key, the second 32 are cached as the
// keystream for the message's first 32 ciphertext bytes. See nacl_box.h's
// file comment for why block 0 is split at byte 32, not reused whole or
// discarded whole.
void extract_block0(XSalsa20Keystream &ks, uint8_t mac_key[32],
                    uint8_t first32[32]) {
  uint8_t block0[64];
  ks.seek_block(0);
  ks.squeeze(block0, 64);
  memcpy(mac_key, block0, 32);
  memcpy(first32, block0 + 32, 32);
  crypto_wipe(block0, sizeof block0);
}

} // namespace

bool box_beforenm(uint8_t precom[32], const uint8_t pk[32], const uint8_t sk[32]) {
  uint8_t shared[32];
  crypto_x25519(shared, sk, pk);

  static const uint8_t zero32[32] = {0};
  if (crypto_verify32(shared, zero32) == 0) {
    // Small-order (or otherwise degenerate) peer public key: X25519 landed
    // on the all-zero point. Reject rather than derive a key from it.
    crypto_wipe(shared, sizeof shared);
    return false;
  }

  const uint8_t zero16[16] = {0};
  hsalsa20(precom, zero16, shared);
  crypto_wipe(shared, sizeof shared);
  return true;
}

void secretbox_seal(uint8_t *out, const uint8_t *pt, size_t n,
                    const uint8_t nonce[24], const uint8_t key[32]) {
  XSalsa20Keystream ks;
  ks.init(key, nonce);
  uint8_t mac_key[32], first32[32];
  extract_block0(ks, mac_key, first32);

  uint8_t *ct = out + 16;
  size_t first = n < 32 ? n : 32;
  for (size_t i = 0; i < first; ++i)
    ct[i] = pt[i] ^ first32[i];
  if (n > 32)
    ks.xor_stream(pt + 32, ct + 32, n - 32);

  crypto_poly1305_ctx poly;
  crypto_poly1305_init(&poly, mac_key);
  crypto_poly1305_update(&poly, ct, n);
  crypto_poly1305_final(&poly, out);

  crypto_wipe(mac_key, sizeof mac_key);
  crypto_wipe(first32, sizeof first32);
}

bool secretbox_open(uint8_t *pt, const uint8_t *in, size_t n_ct,
                    const uint8_t nonce[24], const uint8_t key[32]) {
  XSalsa20Keystream ks;
  ks.init(key, nonce);
  uint8_t mac_key[32], first32[32];
  extract_block0(ks, mac_key, first32);

  const uint8_t *ct = in + 16;
  crypto_poly1305_ctx poly;
  crypto_poly1305_init(&poly, mac_key);
  crypto_poly1305_update(&poly, ct, n_ct);
  uint8_t computed[16];
  crypto_poly1305_final(&poly, computed);

  // Constant-time compare -- never memcmp (DEVELOPER.md, CURVE invariant 6).
  bool ok = crypto_verify16(computed, in) == 0;

  crypto_wipe(mac_key, sizeof mac_key);
  crypto_wipe(computed, sizeof computed);

  if (!ok) {
    crypto_wipe(first32, sizeof first32);
    return false;
  }

  size_t first = n_ct < 32 ? n_ct : 32;
  for (size_t i = 0; i < first; ++i)
    pt[i] = ct[i] ^ first32[i];
  if (n_ct > 32)
    ks.xor_stream(ct + 32, pt + 32, n_ct - 32);

  crypto_wipe(first32, sizeof first32);
  return true;
}

// -----------------------------------------------------------------------
// SecretboxSeal
// -----------------------------------------------------------------------

void SecretboxSeal::init(const uint8_t key[32], const uint8_t nonce[24]) {
  _ks.init(key, nonce);
  uint8_t mac_key[32];
  extract_block0(_ks, mac_key, _first32);
  crypto_poly1305_init(&_poly, mac_key);
  crypto_wipe(mac_key, sizeof mac_key);
  _pos = 0;
}

void SecretboxSeal::xor_next(const uint8_t *pt, uint8_t *ct, size_t n) {
  size_t done = 0;
  while (done < n && _pos < 32) {
    ct[done] = pt[done] ^ _first32[_pos];
    ++done;
    ++_pos;
  }
  if (done < n) {
    _ks.xor_stream(pt + done, ct + done, n - done);
    _pos += (n - done);
  }
}

void SecretboxSeal::absorb(const uint8_t *pt, size_t n) {
  uint8_t scratch[64];
  size_t done = 0;
  while (done < n) {
    size_t chunk = (n - done) < sizeof(scratch) ? (n - done) : sizeof(scratch);
    xor_next(pt + done, scratch, chunk);
    crypto_poly1305_update(&_poly, scratch, chunk);
    done += chunk;
  }
  crypto_wipe(scratch, sizeof scratch);
}

void SecretboxSeal::tag(uint8_t out[16]) { crypto_poly1305_final(&_poly, out); }

void SecretboxSeal::restart() {
  // Regenerate block 0 from the keystream generator's own cached subkey --
  // no need to re-supply the original key/nonce (see the header: this is
  // exactly why they are not stored as members). Poly1305 state is not
  // touched: pass 2 never re-authenticates, it only reproduces ciphertext.
  uint8_t block0[64];
  _ks.seek_block(0);
  _ks.squeeze(block0, 64);
  memcpy(_first32, block0 + 32, 32);
  crypto_wipe(block0, sizeof block0);
  _pos = 0;
}

void SecretboxSeal::encrypt(const uint8_t *pt, uint8_t *ct, size_t n) {
  xor_next(pt, ct, n);
}

// -----------------------------------------------------------------------
// SecretboxOpen
// -----------------------------------------------------------------------

void SecretboxOpen::init(const uint8_t key[32], const uint8_t nonce[24],
                         const uint8_t tag[16]) {
  _ks.init(key, nonce);
  uint8_t mac_key[32];
  extract_block0(_ks, mac_key, _first32);
  crypto_poly1305_init(&_poly, mac_key);
  crypto_wipe(mac_key, sizeof mac_key);
  memcpy(_expected_tag, tag, 16);
  _pos = 0;
}

void SecretboxOpen::xor_next(const uint8_t *ct, uint8_t *pt, size_t n) {
  size_t done = 0;
  while (done < n && _pos < 32) {
    pt[done] = ct[done] ^ _first32[_pos];
    ++done;
    ++_pos;
  }
  if (done < n) {
    _ks.xor_stream(ct + done, pt + done, n - done);
    _pos += (n - done);
  }
}

void SecretboxOpen::update(const uint8_t *ct, uint8_t *pt, size_t n) {
  // Authenticate over the ciphertext exactly as received, independent of
  // the plaintext this call also produces -- finish() is what actually
  // proves any of it genuine (see the header: plaintext here is
  // provisional).
  crypto_poly1305_update(&_poly, ct, n);
  xor_next(ct, pt, n);
}

bool SecretboxOpen::finish() {
  uint8_t computed[16];
  crypto_poly1305_final(&_poly, computed);
  bool ok = crypto_verify16(computed, _expected_tag) == 0;
  crypto_wipe(computed, sizeof computed);
  crypto_wipe(_expected_tag, sizeof _expected_tag);
  return ok;
}

} // namespace Mads
