// Phase 6: the Agent-level CURVE API and the rejected-handshake backoff.
//
// Skipped cleanly unless MADS_BROKER_HOST and MADS_CURVE_KEYS_DIR are set;
// needs a `mads broker --crypto` whose keys directory holds broker.pub and
// uno_r4.{pub,key}, with the broker restarted after uno_r4.pub was added.
//
//   MADS_BROKER_HOST=127.0.0.1 MADS_CURVE_KEYS_DIR=/path/to/keys \
//     ./build/test_curve_agent
#include "mads_agent.hpp"
#include "z85.hpp"

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

static const char Z85_ALPHA[] =
    "0123456789abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";

/// Reads a 40-character Z85 key file as written by `mads --keypair`.
static bool load_z85(const char *dir, const char *name, char out[41]) {
  char path[512];
  std::snprintf(path, sizeof(path), "%s/%s", dir, name);
  std::FILE *f = std::fopen(path, "rb");
  if (!f)
    return false;
  char buf[64] = {0};
  size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
  std::fclose(f);
  while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
    buf[--n] = '\0';
  if (n != 40)
    return false;
  std::memcpy(out, buf, 41);
  return true;
}

/// Z85 encoder, test-only: the library never needs to produce Z85, but
/// building an unauthorised *keypair* to feed set_crypto() does.
static void z85_encode(const uint8_t in[32], char out[41]) {
  size_t o = 0;
  for (size_t i = 0; i < 32; i += 4) {
    uint32_t v = (static_cast<uint32_t>(in[i]) << 24) |
                 (static_cast<uint32_t>(in[i + 1]) << 16) |
                 (static_cast<uint32_t>(in[i + 2]) << 8) |
                 static_cast<uint32_t>(in[i + 3]);
    char tmp[5];
    for (int j = 4; j >= 0; --j) {
      tmp[j] = Z85_ALPHA[v % 85];
      v /= 85;
    }
    for (int j = 0; j < 5; ++j)
      out[o++] = tmp[j];
  }
  out[40] = '\0';
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

int main() {
  const char *host = std::getenv("MADS_BROKER_HOST");
  const char *keys_dir = std::getenv("MADS_CURVE_KEYS_DIR");
  if (!host || !*host || !keys_dir || !*keys_dir) {
    std::printf("test_curve_agent: SKIPPED (set MADS_BROKER_HOST and "
                "MADS_CURVE_KEYS_DIR)\n");
    return 0;
  }
  const char *se = std::getenv("MADS_CURVE_SETTINGS");
  const uint16_t port_se = se ? (uint16_t)std::atoi(se) : 9192;

  char client_pub[41], client_sec[41], broker_pub[41];
  if (!load_z85(keys_dir, "uno_r4.pub", client_pub) ||
      !load_z85(keys_dir, "uno_r4.key", client_sec) ||
      !load_z85(keys_dir, "broker.pub", broker_pub)) {
    std::fprintf(stderr, "test_curve_agent: FAILED -- cannot load keys\n");
    return 1;
  }

  // --- 1. set_crypto() rejects malformed keys before anything else --------
  {
    Mads::Agent a("reject_probe");
    char short_key[40];
    std::memcpy(short_key, client_pub, 39);
    short_key[39] = '\0';
    check(!a.set_crypto(short_key, client_sec, broker_pub),
          "39-character key refused");
    char bad_char[41];
    std::memcpy(bad_char, client_pub, 41);
    bad_char[3] = ' '; // space is not in the Z85 alphabet
    check(!a.set_crypto(bad_char, client_sec, broker_pub),
          "out-of-alphabet character refused");
    check(!a.crypto_enabled(), "a refused set_crypto leaves CURVE disarmed");
    check(a.set_crypto(client_pub, client_sec, broker_pub),
          "valid keys accepted");
    check(a.crypto_enabled(), "crypto_enabled() after a good set_crypto");
  }

  // --- 2. A real CURVE begin() + publish through the Agent ----------------
  {
    Mads::Agent a("curve_agent");
    check(a.set_crypto(client_pub, client_sec, broker_pub), "arm agent");
    const bool ok = a.begin("unused-ssid", "unused-pass", host, port_se,
                            "test_agent", "curve_agent", 5000);
    if (!ok)
      std::fprintf(stderr, "  begin() failed: CurveError::%s\n",
                   err_name(a.last_curve_error()));
    check(ok, "begin() over CURVE (settings REQ is encrypted too)");
    check(a.settings_ok(), "settings parsed from an encrypted reply");
    if (ok) {
      JsonDocument doc;
      doc["source"] = "curve_agent";
      doc["value"] = 7;
      check(a.publish(doc), "publish() over CURVE");
      std::printf("  begin() OK -- frontend=%u backend=%u fps=%d\n",
                  a.frontend_port(), a.backend_port(), a.timecode_fps());
    }
  }

  // --- 3. The two ways a client key goes wrong are distinguishable --------
  // Worth separating, because the fix differs and these codes are the only
  // diagnostic a user gets:
  //   * a consistent keypair the broker does not know -> ZAP denies it and
  //     the broker replies ERROR -> CurveError::rejected. Fix: copy the .pub
  //     into the broker's keys dir and RESTART the broker.
  //   * a public and secret that do not belong together (one of the two
  //     lines mistyped) -> the vouch box cannot be opened, so the broker
  //     drops the connection before authentication runs and logs no ZAP
  //     entry at all -> CurveError::disconnected. Fix: re-copy both lines.
  {
    Mads::Agent a("mismatch_probe");
    char mismatched[41];
    std::memcpy(mismatched, client_pub, 41);
    bool armed = false;
    for (size_t i = 0; i < sizeof(Z85_ALPHA) - 1 && !armed; ++i) {
      if (Z85_ALPHA[i] == client_pub[0])
        continue;
      mismatched[0] = Z85_ALPHA[i];
      armed = a.set_crypto(mismatched, client_sec, broker_pub);
    }
    check(armed, "built a public that does not match the secret");
    a.begin("unused-ssid", "unused-pass", host, port_se, "test_agent",
            "mismatch_probe", 3000);
    check(a.last_curve_error() == Mads::CurveError::disconnected,
          "mismatched key pair -> CurveError::disconnected");
    std::printf("  mismatched public/secret -> CurveError::%s\n",
                err_name(a.last_curve_error()));
  }

  // --- 4. The rejected-handshake backoff ----------------------------------
  // Uses a *consistent* keypair the broker has never heard of, derived from
  // a fixed secret. That is the failure the backoff exists for: the .pub was
  // never copied over, or the broker was not restarted after it was. It is
  // deterministic, costs ~180 ms of X25519 per attempt, and never self-heals.
  {
    Mads::Agent a("backoff_probe");
    uint8_t sec[32], pub[32];
    std::memset(sec, 0x5C, sizeof(sec));
    sec[0] &= 248;
    sec[31] &= 127;
    sec[31] |= 64;
    crypto_x25519_public_key(pub, sec);
    char sec_z85[41], pub_z85[41];
    z85_encode(sec, sec_z85);
    z85_encode(pub, pub_z85);
    check(a.set_crypto(pub_z85, sec_z85, broker_pub),
          "unauthorised but self-consistent keypair arms");

    // Small numbers so the test does not spend real seconds waiting; the
    // doubling is what matters, not the absolute values.
    a.set_reconnect_interval(20);
    a.set_curve_backoff_max(320);
    check(a.curve_backoff() == 20,
          "set_reconnect_interval() resets the backoff");

    uint32_t seen[6] = {0};
    for (int i = 0; i < 6; ++i) {
      // begin() runs fetch_settings() directly, so each call is exactly one
      // handshake attempt -- no waiting on the rate limiter.
      a.begin("unused-ssid", "unused-pass", host, port_se, "test_agent",
              "backoff_probe", 3000);
      seen[i] = a.curve_backoff();
    }
    check(a.last_curve_error() == Mads::CurveError::rejected,
          "unauthorised key reports CurveError::rejected");
    std::printf("  backoff after each rejection: %u %u %u %u %u %u ms\n",
                seen[0], seen[1], seen[2], seen[3], seen[4], seen[5]);
    check(seen[0] == 40 && seen[1] == 80 && seen[2] == 160 && seen[3] == 320,
          "backoff doubles on each rejection");
    check(seen[4] == 320 && seen[5] == 320,
          "backoff saturates at curve_backoff_max()");

    // A good handshake must clear it -- otherwise a board that was once
    // misconfigured stays slow forever after being fixed.
    check(a.set_crypto(client_pub, client_sec, broker_pub), "re-arm correctly");
    const bool ok = a.begin("unused-ssid", "unused-pass", host, port_se,
                            "test_agent", "backoff_probe", 5000);
    check(ok, "begin() succeeds once the key is authorised");
    check(a.curve_backoff() == 20,
          "a successful handshake resets the backoff");
  }

  std::printf("test_curve_agent: %d checks, %d failures\n", g_checks,
              g_failures);
  return g_failures ? 1 : 0;
}
