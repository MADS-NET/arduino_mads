#pragma once
// Entropy source interface for CURVE's transient keypair and vouch nonce.
// CURVE_PLAN.md Sec 1 non-negotiable 1: entropy_fill() returning false MUST
// be fatal to any caller -- there is no fallback to random()/micros()/
// analogRead(). A weak transient key destroys forward secrecy silently.
//
// Two backends implement this, selected by the board macros the Arduino
// build vs. the desktop build define (see entropy_ra4m1.cpp/
// entropy_desktop.cpp -- each is guarded so only one is ever compiled for
// a given target, and both compile to nothing at all when
// MADS_ENABLE_CURVE is undefined).
#ifdef MADS_ENABLE_CURVE
#include <cstddef>
#include <cstdint>

namespace Mads {

/// One-time bring-up: on the board, initialises the SCE TRNG and runs a
/// crude health check on its first output; on the desktop, opens
/// /dev/urandom. Safe to call more than once -- the result is cached and
/// returned again. Returns false if no usable source exists.
bool entropy_init();

/// Fills `out` with `n` bytes of entropy. Calls entropy_init() itself if
/// it has not run yet. Returns false if the source is unavailable or
/// failed its health check -- callers MUST fail closed, per the
/// non-negotiable above.
bool entropy_fill(uint8_t *out, size_t n);

} // namespace Mads
#endif // MADS_ENABLE_CURVE
