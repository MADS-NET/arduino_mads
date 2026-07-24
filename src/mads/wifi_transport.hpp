#pragma once
#include "transport.hpp"
#include <WiFiS3.h>

namespace Mads {

/// Transport over the UNO R4 WiFi's WiFiClient (WiFiS3 library).
class WifiTransport : public Transport {
public:
  WifiTransport() = default;

  bool connect(const char *host, uint16_t port) override {
    close();
    return _client.connect(host, port) == 1;
  }

  bool connected() override { return _client.connected(); }

  void close() override {
    if (_client.connected())
      _client.stop();
  }

  bool write(const uint8_t *data, size_t len) override {
    if (len == 0)
      return true;
    return _client.write(data, len) == len;
  }

  int read(uint8_t *buf, size_t len, uint32_t timeout_ms) override {
    size_t got = 0;
    uint32_t start = millis();
    while (got < len) {
      int avail = _client.available();
      if (avail > 0) {
        int n = _client.read(buf + got, len - got);
        if (n <= 0)
          break;
        got += static_cast<size_t>(n);
        continue;
      }
      if (!_client.connected())
        break;
      if (millis() - start >= timeout_ms)
        break;
    }
    return static_cast<int>(got);
  }

  bool available() override { return _client.available() > 0; }

private:
  WiFiClient _client;
};

} // namespace Mads
