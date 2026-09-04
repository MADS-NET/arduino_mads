#pragma once
#include <cstddef>
#include <cstdint>

namespace Mads {

/**
 * Abstract byte-stream transport: a blocking-with-timeout TCP-like
 * connection, with no framing of its own. ZmtpSession is written purely
 * against this interface so it can run either over WifiTransport (on an
 * Arduino board) or over a plain POSIX socket (in a desktop unit test
 * against a real mads-broker), with no code duplicated or diverging between
 * the two.
 */
class Transport {
public:
  virtual ~Transport() = default;

  virtual bool connect(const char *host, uint16_t port) = 0;
  virtual bool connected() = 0;
  virtual void close() = 0;

  virtual bool write(const uint8_t *data, size_t len) = 0;

  /**
   * Reads up to `len` bytes, blocking until either `len` bytes have
   * arrived, the connection drops, or `timeout_ms` elapses.
   *
   * @return the number of bytes actually placed in `buf`; may be less than
   *  `len` on timeout or disconnection.
   */
  virtual int read(uint8_t *buf, size_t len, uint32_t timeout_ms) = 0;

  /// True if at least one byte can be read without blocking.
  virtual bool available() = 0;
};

} // namespace Mads
