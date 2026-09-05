#include "z85.hpp"
#ifdef MADS_ENABLE_CURVE

namespace Mads {

namespace {

// The ZeroMQ Z85 alphabet, in value order (RFC 32/Z85).
const char ALPHABET[] = "0123456789abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
constexpr uint32_t BASE = 85;
constexpr size_t Z85_CHARS = 40;
constexpr size_t RAW_BYTES = 32;

/// Character to value, or 255 if it is not in the alphabet. A linear scan of
/// 85 entries, done 40 times, once at startup -- a lookup table would be 256
/// bytes of flash to save microseconds nobody is waiting for.
uint8_t value_of(char c) {
  for (uint8_t i = 0; i < BASE; ++i)
    if (ALPHABET[i] == c)
      return i;
  return 255;
}

} // namespace

bool z85_decode(const char *in, uint8_t out[32]) {
  if (!in)
    return false;

  // Exact length: walk to the NUL rather than trusting a count.
  size_t n = 0;
  while (in[n] != '\0') {
    if (++n > Z85_CHARS)
      return false; // too long
  }
  if (n != Z85_CHARS)
    return false; // too short

  uint8_t decoded[RAW_BYTES];
  size_t o = 0;
  for (size_t i = 0; i < Z85_CHARS; i += 5) {
    // 85^5 - 1 exceeds 2^32 - 1, so accumulate wide and range-check: a
    // 5-character group can be entirely in-alphabet and still not encode a
    // 32-bit word.
    uint64_t v = 0;
    for (size_t j = 0; j < 5; ++j) {
      const uint8_t d = value_of(in[i + j]);
      if (d == 255)
        return false; // character outside the alphabet
      v = v * BASE + d;
    }
    if (v > 0xFFFFFFFFull)
      return false;
    decoded[o++] = static_cast<uint8_t>(v >> 24);
    decoded[o++] = static_cast<uint8_t>(v >> 16);
    decoded[o++] = static_cast<uint8_t>(v >> 8);
    decoded[o++] = static_cast<uint8_t>(v);
  }

  // Only touch the caller's buffer once the whole input has validated.
  for (size_t i = 0; i < RAW_BYTES; ++i)
    out[i] = decoded[i];
  return true;
}

} // namespace Mads

#endif // MADS_ENABLE_CURVE
