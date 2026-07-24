#pragma once
#include <cstddef>
#include <cstdint>

namespace Mads {

/**
 * A tiny, purpose-built scanner for the settings reply -- NOT a general TOML
 * parser. The broker sends the *entire* mads.ini file text to every agent
 * (several KB and growing), which rules out "buffer the whole reply, then
 * parse" on a 32KB-RAM device. This scanner instead consumes the reply
 * byte-by-byte (or in small chunks) as it arrives off the wire, line by
 * line, extracting:
 *
 * - the three scalar keys this library itself needs from the shared
 *   `[agents]` section: `frontend_address`, `backend_address` (only the
 *   trailing `:<port>` digits are kept -- see the host-substitution note in
 *   mads_agent.hpp) and `timecode_fps`;
 * - every `key = value` line found in one other, caller-chosen section (set
 *   via watch_section() -- typically the agent's own name, e.g. `[uno_r4]`),
 *   stored verbatim as raw text and exposed via raw_value()/int_value()/
 *   int_array() so a sketch can read its own per-agent configuration (pin
 *   lists, loop delays, etc.) the same way the desktop Agent's subclasses
 *   read their settings, without this library needing to know the key
 *   names in advance.
 *
 * Limitations (acceptable for this narrow purpose): single-line
 * `key = "value"` / `key = number` / `key = [n, n, ...]` entries only, no
 * inline tables/multi-line strings/escaped quotes, and only up to
 * MAX_ENTRIES watched-section keys (extras are silently dropped).
 */
class TomlScan {
public:
  TomlScan() = default;

  /// Also capture every key/value pair found in the section named `name`
  /// (e.g. the agent's own name). Call before feed(); `name` must outlive
  /// the scan (a string literal or the caller's own agent-name buffer is
  /// fine).
  void watch_section(const char *name) { _watch_name = name; }

  void feed(uint8_t byte);
  void feed(const uint8_t *data, size_t len);

  /// Must be called once after the last feed() call: flushes a final line
  /// still sitting in the line buffer if the fed data didn't end in '\n'
  /// (the settings reply is a raw file's bytes, not guaranteed to end with
  /// a trailing newline).
  void finish();

  /// True once the three shared `[agents]` keys have been found. Does NOT
  /// reflect whether the watched section (if any) has been fully seen --
  /// callers that set watch_section() should keep feeding until the whole
  /// settings reply has been consumed.
  bool done() const { return _done; }

  uint16_t frontend_port() const { return _frontend_port; }
  uint16_t backend_port() const { return _backend_port; }
  int timecode_fps() const { return _timecode_fps; }

  /// Raw (trimmed) text of `key` as found in the watched section, or
  /// nullptr if not present (not found, or MAX_ENTRIES was exceeded).
  const char *raw_value(const char *key) const;
  int int_value(const char *key, int default_value) const;
  /// Parses a bracketed integer list like "[0, 2, 4]"; returns the count
  /// written into `out` (capped at `max`).
  size_t int_array(const char *key, int *out, size_t max) const;

private:
  void on_line(const char *line, size_t len);
  void try_match_port(const char *line, size_t len, const char *key,
                      uint16_t &port_out);
  void try_match_fps(const char *line, size_t len);
  void capture_entry(const char *line, size_t len);

  static constexpr size_t LINE_BUF_SIZE = 128;
  static constexpr size_t MAX_ENTRIES = 8;
  static constexpr size_t KEY_CAP = 16;
  static constexpr size_t VALUE_CAP = 40;

  struct Entry {
    char key[KEY_CAP];
    char value[VALUE_CAP];
  };

  char _line_buf[LINE_BUF_SIZE];
  size_t _line_len = 0;
  bool _in_agents_section = false;
  bool _done = false;
  uint16_t _frontend_port = 0;
  uint16_t _backend_port = 0;
  int _timecode_fps = 0;

  const char *_watch_name = nullptr;
  bool _in_watched_section = false;
  Entry _entries[MAX_ENTRIES];
  size_t _entry_count = 0;
};

} // namespace Mads
