/*
 * Vendored Monocypher, version 4.0.2, commit 0d85f98c9d9b0227e42cf795cb527dff372b40a4
 * (https://github.com/LoupVaillant/Monocypher, tag "4.0.2").
 *
 * monocypher.h and monocypher.c.inc are the upstream monocypher.h and
 * monocypher.c files, byte-for-byte, fetched directly from that tag and
 * never edited -- do not edit them for any reason. monocypher.c was
 * renamed to monocypher.c.inc solely so the Arduino builder (which
 * compiles every top-level .c/.cpp file it finds under src/) does not try
 * to compile it directly; it is pulled in below, guarded, instead.
 *
 * This is the only translation unit that actually compiles Monocypher, and
 * it does so only when MADS_ENABLE_CURVE is defined -- so a disabled build
 * carries zero Monocypher object code (CURVE_PLAN.md Sec 7.1: "provably
 * absent from a build with MADS_ENABLE_CURVE undefined").
 *
 * Only crypto_x25519, crypto_x25519_public_key, crypto_verify16/32 and
 * crypto_poly1305* are used elsewhere in this library; everything else
 * Monocypher provides (EdDSA, BLAKE2b, the AEAD/argon2 helpers, ...) is
 * still compiled here (there is no per-function opt-out short of editing
 * the vendored file, which is disallowed) but is unreferenced and dropped
 * by the linker's --gc-sections.
 */
#ifdef MADS_ENABLE_CURVE
#include "monocypher.c.inc"
#endif
