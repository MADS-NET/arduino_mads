#pragma once
// Z85 (ZeroMQ base-85) decoding, for the printable key form `mads --keypair`
// writes. Only decoding: nothing in this library ever needs to produce Z85.
#ifdef MADS_ENABLE_CURVE

#include <cstddef>
#include <cstdint>

namespace Mads {

/**
 * Decodes exactly 40 Z85 characters into 32 raw bytes -- the size and shape
 * of every key file `mads --keypair=<name>` writes (a single 40-character
 * line, no trailing newline).
 *
 * Deliberately strict, because the failure it guards against is a user
 * pasting a key wrong into `arduino_secrets.h` and getting a handshake that
 * fails for no visible reason:
 *   - `in` must be NUL-terminated and exactly 40 characters. Not 39, not 41,
 *     and no leading or trailing whitespace -- the caller pastes a literal,
 *     so anything else is a mistake worth reporting rather than tolerating.
 *   - every character must be in the Z85 alphabet.
 *   - each 5-character group must fit in 32 bits. Z85 can express values up
 *     to 85^5 - 1, which is larger than 2^32 - 1, so some well-formed-looking
 *     strings are still not valid Z85.
 *
 * @return false and leaves `out` untouched on any of those.
 */
bool z85_decode(const char *in, uint8_t out[32]);

} // namespace Mads

#endif // MADS_ENABLE_CURVE
