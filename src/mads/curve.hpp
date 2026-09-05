#pragma once
// CurveZMQ handshake: greeting-complete transport in, armed CurveState out.
// Everything here compiles to nothing unless MADS_ENABLE_CURVE is defined
// (CURVE_PLAN.md Sec 2 -- this file's guard is one of the budgeted #ifdef
// blocks).
#ifdef MADS_ENABLE_CURVE

#include "crypto/nacl_box.h"
#include "transport.hpp"
#include <cstddef>
#include <cstdint>

namespace Mads {

/// The permanent keys, raw (already Z85-decoded -- decoding is Phase 6's
/// job, this layer never sees the printable form).
///   client_public / client_secret : C / c, this board's identity
///   server_public                 : S, the broker's advertised key
struct CurveKeys {
  uint8_t client_public[32];
  uint8_t client_secret[32];
  uint8_t server_public[32];
};

/// Per-connection CURVE state. Created and destroyed with the transport --
/// never carried across a reconnect (CURVE_PLAN.md Sec 1 non-negotiable 2:
/// reusing a (precom, nonce) pair is catastrophic).
struct CurveState {
  uint8_t precom[32];  ///< beforenm(S', c') -- the MESSAGE key
  uint64_t nonce_out;  ///< next outgoing short nonce; 1 for HELLO, 2 for
                       ///< INITIATE, so a completed handshake leaves it at 3
  uint64_t nonce_in;   ///< last accepted peer short nonce
  bool ready;          ///< true only after READY has been opened

  /// Zeroises everything, including `precom`. Called before every handshake
  /// and on every failure path.
  void wipe();
};

/// Why the last curve_handshake() failed. `rejected` is the one worth
/// recognising on sight: the broker sent ERROR, which in practice means
/// this board's .pub is not in the broker's keys directory, or the broker
/// was not restarted after it was added there.
enum class CurveError : uint8_t {
  none,
  no_entropy,  ///< entropy_fill() failed -- fatal, never falls back
  greeting,    ///< peer greeting missing/not CURVE (raised by the caller)
  welcome,     ///< WELCOME malformed, wrong length, or wrong command name
  mac,         ///< a box failed to open: wrong key, or a tampered frame
  rejected,    ///< broker sent ERROR (see above)
  timeout,     ///< transport read returned short while still connected
  disconnected,///< peer closed the connection mid-handshake (see below)
  protocol     ///< anything else structurally wrong
};

// `disconnected` is not in CURVE_PLAN.md Sec 4.1's list, and is here because
// testing against a real broker showed the plan's Sec 4.2 expectation to be
// unreachable. The plan predicts a wrong `server_public` surfaces as
// CurveError::mac, "WELCOME open fails". It cannot: HELLO is sealed with
// beforenm(S, c'), so a wrong S means the *broker* cannot open our HELLO and
// it drops the TCP connection without replying -- verified, with no ZAP entry
// logged at all. The client therefore never sees a WELCOME to fail on.
//
// Without this value that case reports `timeout`, which is exactly the
// "indistinguishable from a dropped connection" outcome Sec 4.1 exists to
// prevent, for what is a very ordinary misconfiguration (copying the wrong
// broker .pub). Best-effort: it rests on Transport::connected() being
// accurate right after a short read, which is reliable on a POSIX socket and
// only advisory on WiFiClient.

/**
 * Runs HELLO -> WELCOME -> INITIATE -> READY over `t`.
 *
 * **The greeting is NOT done here**, which deviates from CURVE_PLAN.md
 * Phase 4's step list on purpose. The greeting's mechanism field is the
 * only part of it that differs between NULL and CURVE, while `minor = 0`
 * is load-bearing for CURVE specifically (it is what keeps SUBSCRIBE an
 * ordinary frame rather than a ZMTP 3.1 command -- see ZmtpSession's class
 * comment and Appendix A.1). Duplicating those 64 bytes here would create
 * two greeting implementations that must agree on that byte forever.
 * ZmtpSession::handshake() sends and validates the greeting for both
 * mechanisms and calls this with the transport already past it.
 *
 * On success `st` is armed for MESSAGE framing and `st.nonce_out == 3`.
 * On any failure `st` is wiped, every transient secret is wiped, and the
 * reason is available from curve_last_error().
 *
 * All working buffers are file-static, not locals (CURVE_PLAN.md Sec 7.2).
 * That makes this function, like the rest of the library, safe for exactly
 * one connection at a time -- which is what the Agent does.
 */
bool curve_handshake(Transport &t, const CurveKeys &k, const char *socket_type,
                     uint32_t timeout_ms, CurveState &st);

/// Reason the most recent curve_handshake() failed. Module-scoped rather
/// than returned through `st`, because a failed handshake wipes `st`.
CurveError curve_last_error();

/// Records a failure that happened before curve_handshake() was reached --
/// specifically a greeting that never got as far as HELLO. Without this the
/// `greeting` code would be unreachable, since ZmtpSession owns the greeting
/// for both mechanisms and would otherwise leave a stale reason behind.
void curve_note_error(CurveError e);

} // namespace Mads

#endif // MADS_ENABLE_CURVE
