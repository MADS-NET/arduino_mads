// Phase 2 crypto primitive tests: published test vectors plus differential
// and round-trip self-consistency checks (DEVELOPER.md). No
// network, no board -- pure computation against the crypto/ sources.
//
// Every numeric vector below comes from crypto_vectors_nacl.inc (libsodium
// test/default/{core1,core2,core4,box,secretbox}) or crypto_vectors_rfc.inc
// (RFC 7748 Sec 5.2/6.1, RFC 8439 Sec 2.5.2) -- see those files' header
// comments for exact provenance. None of it is hand-derived or invented.
#include "monocypher.h"
#include "nacl_box.h"
#include "salsa20.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <random>

using namespace Mads;

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    ++g_checks;                                                              \
    if (!(cond)) {                                                           \
      ++g_failures;                                                          \
      std::fprintf(stderr, "CHECK FAILED: %s (%s:%d)\n", #cond, __FILE__,    \
                    __LINE__);                                               \
    }                                                                        \
  } while (0)

#define CHECK_BYTES_EQ(a, b, n)                                              \
  CHECK(memcmp((a), (b), (n)) == 0)

#include "crypto_vectors_nacl.inc"
#include "crypto_vectors_rfc.inc"

// ---------------------------------------------------------------------------
// HSalsa20 (core1, core2)
// ---------------------------------------------------------------------------
static void test_hsalsa20_vectors() {
  uint8_t firstkey[32];
  static const uint8_t zero16[16] = {0};
  hsalsa20(firstkey, zero16, k_core1_shared);
  CHECK_BYTES_EQ(firstkey, k_core1_firstkey_expected, 32);

  uint8_t secondkey[32];
  hsalsa20(secondkey, k_core2_nonceprefix, firstkey);
  CHECK_BYTES_EQ(secondkey, k_core2_secondkey_expected, 32);
}

// ---------------------------------------------------------------------------
// Salsa20 raw core block function (core4)
// ---------------------------------------------------------------------------
static void test_salsa20_core_vector() {
  uint8_t out[64];
  salsa20_core(out, k_core4_in, k_core4_key);
  CHECK_BYTES_EQ(out, k_core4_out_expected, 64);
}

// ---------------------------------------------------------------------------
// X25519 (RFC 7748 Sec 5.2, Sec 6.1)
// ---------------------------------------------------------------------------
static void test_x25519_vectors() {
  uint8_t out[32];

  crypto_x25519(out, k_rfc7748_t1_scalar, k_rfc7748_t1_u);
  CHECK_BYTES_EQ(out, k_rfc7748_t1_out_expected, 32);

  crypto_x25519(out, k_rfc7748_t2_scalar, k_rfc7748_t2_u);
  CHECK_BYTES_EQ(out, k_rfc7748_t2_out_expected, 32);

  // Iterated self-composition, one step: k1 = X25519(9-basepoint-scalar, 9).
  static const uint8_t base_k[32] = {9};
  static const uint8_t base_u[32] = {9};
  crypto_x25519(out, base_k, base_u);
  CHECK_BYTES_EQ(out, k_rfc7748_iter1_out_expected, 32);

  // Sec 6.1 Diffie-Hellman example.
  uint8_t alice_pub[32], bob_pub[32], shared_a[32], shared_b[32];
  crypto_x25519_public_key(alice_pub, k_rfc7748_alice_priv);
  CHECK_BYTES_EQ(alice_pub, k_rfc7748_alice_pub_expected, 32);
  crypto_x25519_public_key(bob_pub, k_rfc7748_bob_priv);
  CHECK_BYTES_EQ(bob_pub, k_rfc7748_bob_pub_expected, 32);

  crypto_x25519(shared_a, k_rfc7748_alice_priv, bob_pub);
  crypto_x25519(shared_b, k_rfc7748_bob_priv, alice_pub);
  CHECK_BYTES_EQ(shared_a, k_rfc7748_shared_expected, 32);
  CHECK_BYTES_EQ(shared_b, k_rfc7748_shared_expected, 32);

  // Cross-check against the (independently sourced) NaCl box.c vector:
  // RFC 7748's own DH example uses the exact same key material.
  CHECK_BYTES_EQ(k_rfc7748_alice_priv, k_box_alicesk, 32);
  CHECK_BYTES_EQ(k_rfc7748_bob_pub_expected, k_box_bobpk, 32);
  CHECK_BYTES_EQ(k_rfc7748_shared_expected, k_core1_shared, 32);
}

// ---------------------------------------------------------------------------
// Poly1305 (RFC 8439 Sec 2.5.2)
// ---------------------------------------------------------------------------
static void test_poly1305_vector() {
  uint8_t tag[16];
  crypto_poly1305(tag, k_rfc8439_poly1305_msg, sizeof(k_rfc8439_poly1305_msg),
                  k_rfc8439_poly1305_key);
  CHECK_BYTES_EQ(tag, k_rfc8439_poly1305_tag_expected, 16);

  // Incremental interface must agree with the one-shot call, split at an
  // arbitrary (non-block-aligned) point.
  crypto_poly1305_ctx ctx;
  crypto_poly1305_init(&ctx, k_rfc8439_poly1305_key);
  crypto_poly1305_update(&ctx, k_rfc8439_poly1305_msg, 9);
  crypto_poly1305_update(&ctx, k_rfc8439_poly1305_msg + 9,
                         sizeof(k_rfc8439_poly1305_msg) - 9);
  uint8_t tag2[16];
  crypto_poly1305_final(&ctx, tag2);
  CHECK_BYTES_EQ(tag2, k_rfc8439_poly1305_tag_expected, 16);
}

// ---------------------------------------------------------------------------
// box_beforenm + secretbox_seal/open against the NaCl box.c/secretbox.c
// vector (full X25519 + HSalsa20 + XSalsa20 + Poly1305 stack).
// ---------------------------------------------------------------------------
static void test_box_and_secretbox_vector() {
  uint8_t precom[32];
  bool ok = box_beforenm(precom, k_box_bobpk, k_box_alicesk);
  CHECK(ok);
  CHECK_BYTES_EQ(precom, k_core1_firstkey_expected, 32); // == core1's firstkey

  const uint8_t *pt = k_box_m163 + 32; // 32 leading zero bytes stripped
  const size_t n = sizeof(k_box_m163) - 32; // 131
  uint8_t sealed[16 + 131];
  secretbox_seal(sealed, pt, n, k_box_nonce, precom);
  CHECK_BYTES_EQ(sealed, k_box_tag_and_ciphertext_expected, 16 + n);

  uint8_t opened[131];
  ok = secretbox_open(opened, sealed, n, k_box_nonce, precom);
  CHECK(ok);
  CHECK_BYTES_EQ(opened, pt, n);

  // Same vector, direct secretbox key (secretbox.c's firstkey == precom).
  uint8_t sealed2[16 + 131];
  secretbox_seal(sealed2, pt, n, k_box_nonce, k_core1_firstkey_expected);
  CHECK_BYTES_EQ(sealed2, k_box_tag_and_ciphertext_expected, 16 + n);
}

static void test_box_beforenm_rejects_small_order_key() {
  uint8_t precom[32];
  bool ok = box_beforenm(precom, k_box_small_order_pk, k_box_alicesk);
  CHECK(!ok);
}

// ---------------------------------------------------------------------------
// Differential test: SecretboxSeal (two-pass) vs secretbox_seal (one-shot)
// must produce identical output for random lengths 0..4096.
// ---------------------------------------------------------------------------
static void test_differential_seal(std::mt19937 &rng) {
  std::uniform_int_distribution<int> len_dist(0, 4096);
  std::uniform_int_distribution<int> byte_dist(0, 255);

  uint8_t key[32], nonce[24];
  for (auto &b : key) b = static_cast<uint8_t>(byte_dist(rng));
  for (auto &b : nonce) b = static_cast<uint8_t>(byte_dist(rng));

  static uint8_t pt[4096];
  static uint8_t one_shot[16 + 4096];
  static uint8_t two_pass_tag[16];
  static uint8_t two_pass_ct[4096];

  for (int trial = 0; trial < 40; ++trial) {
    size_t n = static_cast<size_t>(len_dist(rng));
    for (size_t i = 0; i < n; ++i)
      pt[i] = static_cast<uint8_t>(byte_dist(rng));

    secretbox_seal(one_shot, pt, n, nonce, key);

    SecretboxSeal seal;
    seal.init(key, nonce);
    // Absorb in irregular chunks to exercise chunk-boundary handling,
    // including the block-0/byte-32 split landing mid-chunk.
    size_t done = 0;
    while (done < n) {
      size_t chunk = 1 + (byte_dist(rng) % 37);
      if (chunk > n - done)
        chunk = n - done;
      seal.absorb(pt + done, chunk);
      done += chunk;
    }
    seal.tag(two_pass_tag);
    seal.restart();
    done = 0;
    while (done < n) {
      size_t chunk = 1 + (byte_dist(rng) % 53);
      if (chunk > n - done)
        chunk = n - done;
      seal.encrypt(pt + done, two_pass_ct + done, chunk);
      done += chunk;
    }

    CHECK_BYTES_EQ(two_pass_tag, one_shot, 16);
    if (n > 0)
      CHECK_BYTES_EQ(two_pass_ct, one_shot + 16, n);
  }
}

// ---------------------------------------------------------------------------
// Round-trip: SecretboxOpen decodes what SecretboxSeal/secretbox_seal
// produced, for random lengths, chunked arbitrarily on both ends.
// ---------------------------------------------------------------------------
static void test_roundtrip_open(std::mt19937 &rng) {
  std::uniform_int_distribution<int> len_dist(0, 4096);
  std::uniform_int_distribution<int> byte_dist(0, 255);

  uint8_t key[32], nonce[24];
  for (auto &b : key) b = static_cast<uint8_t>(byte_dist(rng));
  for (auto &b : nonce) b = static_cast<uint8_t>(byte_dist(rng));

  static uint8_t pt[4096];
  static uint8_t sealed[16 + 4096];
  static uint8_t recovered[4096];

  for (int trial = 0; trial < 40; ++trial) {
    size_t n = static_cast<size_t>(len_dist(rng));
    for (size_t i = 0; i < n; ++i)
      pt[i] = static_cast<uint8_t>(byte_dist(rng));
    secretbox_seal(sealed, pt, n, nonce, key);

    // One-shot open.
    bool ok = secretbox_open(recovered, sealed, n, nonce, key);
    CHECK(ok);
    if (n > 0)
      CHECK_BYTES_EQ(recovered, pt, n);

    // Streaming open, chunked arbitrarily, mirroring how ZmtpSession would
    // feed ciphertext to it off the wire.
    SecretboxOpen open;
    open.init(key, nonce, sealed);
    size_t done = 0;
    while (done < n) {
      size_t chunk = 1 + (byte_dist(rng) % 29);
      if (chunk > n - done)
        chunk = n - done;
      open.update(sealed + 16 + done, recovered + done, chunk);
      done += chunk;
    }
    ok = open.finish();
    CHECK(ok);
    if (n > 0)
      CHECK_BYTES_EQ(recovered, pt, n);
  }
}

// ---------------------------------------------------------------------------
// Tamper tests: every single-bit flip in the tag, and (for a nonempty
// message) representative bit flips in the ciphertext, must be rejected.
// A different nonce on open must also be rejected.
// ---------------------------------------------------------------------------
static void test_tamper_rejected(std::mt19937 &rng) {
  std::uniform_int_distribution<int> byte_dist(0, 255);

  uint8_t key[32], nonce[24];
  for (auto &b : key) b = static_cast<uint8_t>(byte_dist(rng));
  for (auto &b : nonce) b = static_cast<uint8_t>(byte_dist(rng));

  const size_t n = 200; // spans the block-0/byte-32 split and into block 1
  uint8_t pt[n];
  for (auto &b : pt) b = static_cast<uint8_t>(byte_dist(rng));

  uint8_t sealed[16 + n];
  secretbox_seal(sealed, pt, n, nonce, key);

  uint8_t recovered[n];
  CHECK(secretbox_open(recovered, sealed, n, nonce, key)); // sanity: untampered opens fine

  // Every bit of the 16-byte tag.
  for (int byte_i = 0; byte_i < 16; ++byte_i) {
    for (int bit = 0; bit < 8; ++bit) {
      uint8_t tampered[16 + n];
      memcpy(tampered, sealed, sizeof(tampered));
      tampered[byte_i] ^= static_cast<uint8_t>(1u << bit);
      CHECK(!secretbox_open(recovered, tampered, n, nonce, key));
    }
  }

  // A sample of ciphertext bit flips: first byte (within the reused
  // block-0 second half), byte 31/32 (astride the split), and the last
  // byte (inside block 1+).
  const size_t sample_offsets[] = {0, 31, 32, n - 1};
  for (size_t off : sample_offsets) {
    for (int bit = 0; bit < 8; ++bit) {
      uint8_t tampered[16 + n];
      memcpy(tampered, sealed, sizeof(tampered));
      tampered[16 + off] ^= static_cast<uint8_t>(1u << bit);
      CHECK(!secretbox_open(recovered, tampered, n, nonce, key));
    }
  }

  // Nonce tamper (any bit).
  for (int byte_i = 0; byte_i < 24; ++byte_i) {
    uint8_t tampered_nonce[24];
    memcpy(tampered_nonce, nonce, 24);
    tampered_nonce[byte_i] ^= 0x01;
    CHECK(!secretbox_open(recovered, sealed, n, tampered_nonce, key));
  }

  // Streaming open must reject the same tampered tag via finish().
  uint8_t tampered_tag[16 + n];
  memcpy(tampered_tag, sealed, sizeof(tampered_tag));
  tampered_tag[0] ^= 0x01;
  SecretboxOpen open;
  open.init(key, nonce, tampered_tag);
  open.update(tampered_tag + 16, recovered, n);
  CHECK(!open.finish());
}

int main() {
  test_hsalsa20_vectors();
  test_salsa20_core_vector();
  test_x25519_vectors();
  test_poly1305_vector();
  test_box_and_secretbox_vector();
  test_box_beforenm_rejects_small_order_key();

  std::mt19937 rng(0xC0FFEEu); // fixed seed: deterministic, reproducible runs
  test_differential_seal(rng);
  test_roundtrip_open(rng);
  test_tamper_rejected(rng);

  std::printf("test_crypto_vectors: %d checks, %d failures\n", g_checks,
              g_failures);
  return g_failures == 0 ? 0 : 1;
}
