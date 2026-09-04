// Live CURVE handshake test (CURVE_PLAN.md Phase 4.2).
//
// Skipped cleanly -- exit 0, prints SKIPPED -- unless MADS_BROKER_HOST and
// MADS_CURVE_KEYS_DIR are set, so it is safe to run anywhere.
//
//   MADS_BROKER_HOST=127.0.0.1 MADS_CURVE_KEYS_DIR=/path/to/keys \
//     ./build/test_curve_handshake
//
// The keys directory is the broker's own: it must hold broker.pub (the
// broker's public key, which this client needs as `server_public`) and the
// client's uno_r4.key / uno_r4.pub. The broker must be running with
// `--crypto` and must have been RESTARTED after uno_r4.pub was placed there
// -- CurveAuth::fetch_public_keys() scans *.pub only at startup, and a
// broker that missed the restart rejects with ERROR exactly like an unknown
// key does.
//
// Ports default to the isolated 919x set rather than the usual 909x, so a
// developer's own plain broker can keep running alongside.
#include "curve.hpp"
#include "wifi_transport.hpp"
#include "zmtp_session.hpp"

#include "crypto/monocypher.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

static int g_checks = 0;
static int g_failures = 0;

static void check(bool ok, const char *what) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::fprintf(stderr, "  FAIL: %s\n", what);
  }
}

// --- Z85 -------------------------------------------------------------------
// Decoding lives here rather than in the library on purpose: CURVE_PLAN.md
// Phase 4 takes CurveKeys already decoded, and z85.{hpp,cpp} is Phase 6's
// deliverable. Duplicating 20 lines in a test is cheaper than pulling a
// phase forward.
static const char Z85_ALPHA[] =
    "0123456789abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";

static bool z85_decode(const char *in, size_t in_len, uint8_t *out,
                       size_t out_cap) {
  if (in_len == 0 || in_len % 5 != 0 || in_len / 5 * 4 > out_cap)
    return false;
  size_t o = 0;
  for (size_t i = 0; i < in_len; i += 5) {
    uint32_t v = 0;
    for (int j = 0; j < 5; ++j) {
      char c = in[i + j];
      if (c == '\0')
        return false; // strchr would otherwise match the terminator
      const char *p = std::strchr(Z85_ALPHA, c);
      if (!p)
        return false;
      v = v * 85u + static_cast<uint32_t>(p - Z85_ALPHA);
    }
    out[o++] = static_cast<uint8_t>(v >> 24);
    out[o++] = static_cast<uint8_t>(v >> 16);
    out[o++] = static_cast<uint8_t>(v >> 8);
    out[o++] = static_cast<uint8_t>(v);
  }
  return true;
}

/// Reads a 40-character Z85 key file (as written by `mads --keypair`, which
/// emits no trailing newline) into 32 raw bytes.
static bool load_key(const char *dir, const char *name, uint8_t out[32]) {
  char path[512];
  std::snprintf(path, sizeof(path), "%s/%s", dir, name);
  std::FILE *f = std::fopen(path, "rb");
  if (!f) {
    std::fprintf(stderr, "  cannot open %s\n", path);
    return false;
  }
  char buf[64] = {0};
  size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
  std::fclose(f);
  while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
    buf[--n] = '\0';
  if (n != 40) {
    std::fprintf(stderr, "  %s: expected 40 Z85 chars, got %zu\n", path, n);
    return false;
  }
  return z85_decode(buf, 40, out, 32);
}

static const char *err_name(Mads::CurveError e) {
  switch (e) {
  case Mads::CurveError::none: return "none";
  case Mads::CurveError::no_entropy: return "no_entropy";
  case Mads::CurveError::greeting: return "greeting";
  case Mads::CurveError::welcome: return "welcome";
  case Mads::CurveError::mac: return "mac";
  case Mads::CurveError::rejected: return "rejected";
  case Mads::CurveError::timeout: return "timeout";
  case Mads::CurveError::disconnected: return "disconnected";
  case Mads::CurveError::protocol: return "protocol";
  }
  return "?";
}

/// One handshake attempt against `port` as `socket_type`.
static bool try_handshake(const char *host, uint16_t port,
                          const char *socket_type, const Mads::CurveKeys &keys,
                          uint64_t *nonce_out) {
  Mads::WifiTransport t;
  if (!t.connect(host, port)) {
    std::fprintf(stderr, "  cannot connect to %s:%u\n", host, port);
    return false;
  }
  Mads::ZmtpSession s(t);
  s.set_curve_keys(&keys);
  s.reset();
  bool ok = s.handshake(socket_type, 5000);
  if (ok && nonce_out)
    *nonce_out = s.curve_state().nonce_out;
  t.close();
  return ok;
}

int main() {
  const char *host = std::getenv("MADS_BROKER_HOST");
  const char *keys_dir = std::getenv("MADS_CURVE_KEYS_DIR");
  if (!host || !*host || !keys_dir || !*keys_dir) {
    std::printf("test_curve_handshake: SKIPPED (set MADS_BROKER_HOST and "
                "MADS_CURVE_KEYS_DIR)\n");
    return 0;
  }

  const char *fe = std::getenv("MADS_CURVE_FRONTEND");
  const char *be = std::getenv("MADS_CURVE_BACKEND");
  const char *se = std::getenv("MADS_CURVE_SETTINGS");
  const uint16_t port_fe = fe ? (uint16_t)std::atoi(fe) : 9190;
  const uint16_t port_be = be ? (uint16_t)std::atoi(be) : 9191;
  const uint16_t port_se = se ? (uint16_t)std::atoi(se) : 9192;

  Mads::CurveKeys keys;
  std::memset(&keys, 0, sizeof(keys));
  if (!load_key(keys_dir, "broker.pub", keys.server_public) ||
      !load_key(keys_dir, "uno_r4.pub", keys.client_public) ||
      !load_key(keys_dir, "uno_r4.key", keys.client_secret)) {
    std::fprintf(stderr, "test_curve_handshake: FAILED -- could not load "
                         "keys from %s\n", keys_dir);
    return 1;
  }
  std::printf("test_curve_handshake: keys loaded from %s\n", keys_dir);

  // --- 1. All three socket types complete the handshake -------------------
  // Each socket type sends a different Socket-Type property in its INITIATE
  // metadata, so this covers all three metadata encodings on the wire.
  struct { const char *type; uint16_t port; } cases[] = {
      {"REQ", port_se}, {"PUB", port_fe}, {"SUB", port_be}};
  for (auto &c : cases) {
    uint64_t nonce_out = 0;
    bool ok = try_handshake(host, c.port, c.type, keys, &nonce_out);
    if (!ok)
      std::fprintf(stderr, "  %s on :%u -> CurveError::%s\n", c.type, c.port,
                   err_name(Mads::curve_last_error()));
    check(ok, c.type);
    // HELLO consumed nonce 1 and INITIATE nonce 2, so a completed handshake
    // must leave the counter at 3 -- CURVE_PLAN.md Phase 8 step 5, which
    // exists because a reconnect that restarted it would reuse a nonce.
    if (ok) {
      check(nonce_out == 3, "nonce_out == 3 after handshake");
      if (nonce_out != 3)
        std::fprintf(stderr, "    nonce_out was %llu\n",
                     (unsigned long long)nonce_out);
      std::printf("  %s on :%u OK (nonce_out=%llu)\n", c.type, c.port,
                  (unsigned long long)nonce_out);
    }
  }

  // --- 2. Negative: wrong broker key -> the broker hangs up ---------------
  // CURVE_PLAN.md Sec 4.2 predicts CurveError::mac here, on the reasoning
  // that WELCOME fails to open. That does not happen and cannot: HELLO is
  // sealed with beforenm(S, c'), so a wrong S means the *broker* cannot open
  // our HELLO and drops the connection without replying. Confirmed against a
  // real broker -- it logs no ZAP entry at all for this case, because the
  // connection dies before authentication is ever reached. So the client's
  // observable outcome is a hang-up, one round trip earlier than the plan
  // assumed.
  {
    Mads::CurveKeys bad = keys;
    bad.server_public[0] ^= 0x01;
    bool ok = try_handshake(host, port_fe, "PUB", bad, nullptr);
    check(!ok, "wrong broker key is refused");
    check(Mads::curve_last_error() == Mads::CurveError::disconnected,
          "wrong broker key -> CurveError::disconnected");
    std::printf("  wrong broker key -> CurveError::%s\n",
                err_name(Mads::curve_last_error()));
  }

  // --- 3. Negative: client key the broker does not know -> ERROR ----------
  // This is the failure everyone actually hits in the field, so it gets its
  // own distinguishable code rather than looking like a dropped connection.
  {
    Mads::CurveKeys unknown = keys;
    std::memset(unknown.client_secret, 0x42, 32);
    unknown.client_secret[0] &= 248;
    unknown.client_secret[31] &= 127;
    unknown.client_secret[31] |= 64;
    crypto_x25519_public_key(unknown.client_public, unknown.client_secret);
    bool ok = try_handshake(host, port_fe, "PUB", unknown, nullptr);
    check(!ok, "unknown client key is refused");
    check(Mads::curve_last_error() == Mads::CurveError::rejected,
          "unknown client key -> CurveError::rejected");
    std::printf("  unknown client key -> CurveError::%s\n",
                err_name(Mads::curve_last_error()));
  }

  // --- 4. Negative: broker not running --crypto at all --------------------
  // The other misconfiguration people hit: pointing a CURVE client at a
  // plain broker. It advertises NULL in its greeting, the mechanism compare
  // fails, and the client must say so rather than reporting a vague
  // transport error. Optional -- needs a plain broker to point at.
  if (const char *null_port = std::getenv("MADS_NULL_BROKER_PORT")) {
    bool ok = try_handshake(host, (uint16_t)std::atoi(null_port), "PUB", keys,
                            nullptr);
    check(!ok, "plain broker is refused by a CURVE client");
    check(Mads::curve_last_error() == Mads::CurveError::greeting,
          "plain broker -> CurveError::greeting");
    std::printf("  plain (non-crypto) broker -> CurveError::%s\n",
                err_name(Mads::curve_last_error()));
  }

  std::printf("test_curve_handshake: %d checks, %d failures\n", g_checks,
              g_failures);
  return g_failures ? 1 : 0;
}
