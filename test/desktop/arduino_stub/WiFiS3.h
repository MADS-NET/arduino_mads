// Desktop test fixture standing in for the UNO R4 WiFi core's WiFiS3.h.
//
// This is NOT an emulator: it exposes exactly the surface wifi_transport.hpp
// and mads_agent.cpp use (WiFiClient::connect/connected/stop/write/read/
// available, WiFi.begin/status/localIP/macAddress, WL_CONNECTED), backed by
// a real POSIX TCP socket, so mads_agent.cpp and wifi_transport.hpp compile
// and run unmodified on the desktop against a real mads-broker. WiFi join
// itself is a no-op here -- the desktop already has a network -- so
// WiFi.status() always reports WL_CONNECTED and WiFi.begin() does nothing.
//
// Keep this file small. Anything mads_agent.cpp/wifi_transport.hpp starts
// using that isn't here yet should be added deliberately, not grown ad hoc.
#pragma once

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

using byte = uint8_t;

// ---------------------------------------------------------------------------
// millis()/micros()/delay() -- monotonic clock, process-start epoch.
// ---------------------------------------------------------------------------
inline uint32_t millis() {
  using namespace std::chrono;
  static const steady_clock::time_point t0 = steady_clock::now();
  return static_cast<uint32_t>(
      duration_cast<milliseconds>(steady_clock::now() - t0).count());
}

inline uint32_t micros() {
  using namespace std::chrono;
  static const steady_clock::time_point t0 = steady_clock::now();
  return static_cast<uint32_t>(
      duration_cast<microseconds>(steady_clock::now() - t0).count());
}

inline void delay(uint32_t ms) {
  usleep(static_cast<useconds_t>(ms) * 1000);
}

// ---------------------------------------------------------------------------
// IPAddress -- only what mads_agent.cpp needs: operator[] and formatting.
// ---------------------------------------------------------------------------
class IPAddress {
public:
  IPAddress() { _b[0] = _b[1] = _b[2] = _b[3] = 0; }
  IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    _b[0] = a; _b[1] = b; _b[2] = c; _b[3] = d;
  }
  uint8_t operator[](int i) const { return _b[i]; }

private:
  uint8_t _b[4];
};

// ---------------------------------------------------------------------------
// WiFiClient -- a real blocking POSIX TCP socket underneath.
// ---------------------------------------------------------------------------
class WiFiClient {
public:
  WiFiClient() = default;
  ~WiFiClient() { stop(); }

  // Returns 1 on success, 0 on failure -- matches WiFiClient::connect()'s
  // return convention, which wifi_transport.hpp compares against 1.
  int connect(const char *host, uint16_t port) {
    stop();
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = nullptr;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
      return 0;

    int fd = -1;
    for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
      fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (fd < 0)
        continue;
      if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
        _fd = fd;
        break;
      }
      ::close(fd);
      fd = -1;
    }
    freeaddrinfo(res);
    return _fd >= 0 ? 1 : 0;
  }

  bool connected() {
    if (_fd < 0)
      return false;
    // Non-destructive liveness probe: MSG_PEEK a single byte. 0 means the
    // peer closed; a real error (other than EAGAIN/EWOULDBLOCK) also means
    // dead. This mirrors WiFiClient::connected()'s "still usable" contract
    // without consuming data other calls need.
    uint8_t b;
    ssize_t n = recv(_fd, &b, 1, MSG_PEEK | MSG_DONTWAIT);
    if (n == 0)
      return false;
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
      return false;
    return true;
  }

  void stop() {
    if (_fd >= 0) {
      ::close(_fd);
      _fd = -1;
    }
  }

  size_t write(const uint8_t *data, size_t len) {
    if (_fd < 0)
      return 0;
    size_t sent = 0;
    while (sent < len) {
      ssize_t n = ::send(_fd, data + sent, len - sent, MSG_NOSIGNAL);
      if (n <= 0)
        break;
      sent += static_cast<size_t>(n);
    }
    return sent;
  }

  int available() {
    if (_fd < 0)
      return 0;
    uint8_t b;
    ssize_t n = recv(_fd, &b, 1, MSG_PEEK | MSG_DONTWAIT);
    if (n > 0)
      return 1;
    return 0;
  }

  int read(uint8_t *buf, size_t len) {
    if (_fd < 0)
      return -1;
    ssize_t n = recv(_fd, buf, len, MSG_DONTWAIT);
    if (n == 0)
      return -1; // peer closed
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      return -1;
    }
    return static_cast<int>(n);
  }

private:
  int _fd = -1;
};

// ---------------------------------------------------------------------------
// WiFi -- join is a no-op on the desktop; always reports connected.
// ---------------------------------------------------------------------------
static constexpr int WL_CONNECTED = 3;
static constexpr int WL_IDLE_STATUS = 0;

class WiFiClass {
public:
  void begin(const char * /*ssid*/, const char * /*pass*/) { /* no-op */ }
  int status() { return WL_CONNECTED; }
  IPAddress localIP() { return IPAddress(127, 0, 0, 1); }
  void macAddress(byte *mac) {
    // Fixed, obviously-fake MAC -- deterministic for tests.
    const uint8_t fake[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    memcpy(mac, fake, 6);
  }
};

extern WiFiClass WiFi;
