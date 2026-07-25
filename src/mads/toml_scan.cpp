#include "toml_scan.hpp"
#include <cstring>

namespace Mads {

namespace {

const char *skip_ws(const char *s, const char *end) {
  while (s < end && (*s == ' ' || *s == '\t'))
    ++s;
  return s;
}

const char *rtrim(const char *start, const char *end) {
  while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
    --end;
  return end;
}

} // namespace

void TomlScan::feed(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i)
    feed(data[i]);
}

void TomlScan::feed(uint8_t byte) {
  if (byte == '\r')
    return; // ignore, handle bare \n and \r\n alike
  if (byte == '\n' || _line_len >= LINE_BUF_SIZE - 1) {
    on_line(_line_buf, _line_len);
    _line_len = 0;
    return;
  }
  _line_buf[_line_len++] = static_cast<char>(byte);
}

void TomlScan::finish() {
  if (_line_len > 0) {
    on_line(_line_buf, _line_len);
    _line_len = 0;
  }
}

void TomlScan::reset() {
  _line_len = 0;
  _in_agents_section = false;
  _in_watched_section = false;
  _done = false;
  _frontend_port = 0;
  _backend_port = 0;
  _timecode_fps = 0;
  _entry_count = 0;
}

void TomlScan::on_line(const char *line, size_t len) {
  const char *s = line;
  const char *end = line + len;
  s = skip_ws(s, end);
  if (s >= end || *s == '#')
    return;

  if (*s == '[') {
    const char *close = static_cast<const char *>(memchr(s, ']', end - s));
    if (close) {
      size_t name_len = static_cast<size_t>(close - (s + 1));
      _in_agents_section = (name_len == 6 && strncmp(s + 1, "agents", 6) == 0);
      _in_watched_section = _watch_name != nullptr &&
                            name_len == strlen(_watch_name) &&
                            strncmp(s + 1, _watch_name, name_len) == 0;
    }
    return;
  }

  size_t remaining = static_cast<size_t>(end - s);
  if (_in_agents_section) {
    try_match_port(s, remaining, "frontend_address", _frontend_port);
    try_match_port(s, remaining, "backend_address", _backend_port);
    try_match_fps(s, remaining);
    if (_frontend_port != 0 && _backend_port != 0 && _timecode_fps != 0)
      _done = true;
  } else if (_in_watched_section) {
    capture_entry(s, remaining);
  }
}

void TomlScan::capture_entry(const char *line, size_t len) {
  if (_entry_count >= MAX_ENTRIES)
    return;

  const char *end = line + len;
  const char *eq = static_cast<const char *>(memchr(line, '=', len));
  if (!eq)
    return;

  const char *key_end = rtrim(line, eq);
  size_t key_len = static_cast<size_t>(key_end - line);
  if (key_len == 0 || key_len >= KEY_CAP)
    return;

  const char *val = skip_ws(eq + 1, end);
  const char *val_end = rtrim(val, end);
  size_t val_len = static_cast<size_t>(val_end - val);
  if (val_len >= VALUE_CAP)
    val_len = VALUE_CAP - 1;

  Entry &e = _entries[_entry_count++];
  memcpy(e.key, line, key_len);
  e.key[key_len] = '\0';
  memcpy(e.value, val, val_len);
  e.value[val_len] = '\0';
}

void TomlScan::try_match_port(const char *line, size_t len, const char *key,
                              uint16_t &port_out) {
  size_t key_len = strlen(key);
  if (len < key_len || strncmp(line, key, key_len) != 0)
    return;

  const char *s = line + key_len;
  const char *end = line + len;
  s = skip_ws(s, end);
  if (s >= end || *s != '=')
    return;
  ++s;

  // The value is a quoted URI like "tcp://localhost:9090"; only the port
  // after the last ':' is needed (see mads_agent.hpp for why the host part
  // is discarded).
  const char *colon = nullptr;
  for (const char *p = s; p < end; ++p)
    if (*p == ':')
      colon = p;
  if (!colon)
    return;
  ++colon;

  uint32_t port = 0;
  bool any = false;
  while (colon < end && *colon >= '0' && *colon <= '9') {
    port = port * 10 + static_cast<uint32_t>(*colon - '0');
    ++colon;
    any = true;
  }
  if (any && port > 0 && port <= 65535)
    port_out = static_cast<uint16_t>(port);
}

void TomlScan::try_match_fps(const char *line, size_t len) {
  static const char key[] = "timecode_fps";
  size_t key_len = sizeof(key) - 1;
  if (len < key_len || strncmp(line, key, key_len) != 0)
    return;

  const char *s = line + key_len;
  const char *end = line + len;
  s = skip_ws(s, end);
  if (s >= end || *s != '=')
    return;
  ++s;
  s = skip_ws(s, end);

  int value = 0;
  bool any = false;
  while (s < end && *s >= '0' && *s <= '9') {
    value = value * 10 + (*s - '0');
    ++s;
    any = true;
  }
  if (any && value > 0)
    _timecode_fps = value;
}

const char *TomlScan::raw_value(const char *key) const {
  for (size_t i = 0; i < _entry_count; ++i)
    if (strcmp(_entries[i].key, key) == 0)
      return _entries[i].value;
  return nullptr;
}

int TomlScan::int_value(const char *key, int default_value) const {
  const char *v = raw_value(key);
  if (!v)
    return default_value;

  const char *s = v;
  bool neg = false;
  if (*s == '-') {
    neg = true;
    ++s;
  }
  int result = 0;
  bool any = false;
  while (*s >= '0' && *s <= '9') {
    result = result * 10 + (*s - '0');
    ++s;
    any = true;
  }
  if (!any)
    return default_value;
  return neg ? -result : result;
}

size_t TomlScan::int_array(const char *key, int *out, size_t max) const {
  const char *v = raw_value(key);
  if (!v)
    return 0;

  const char *s = v;
  while (*s == ' ' || *s == '\t')
    ++s;
  if (*s == '[')
    ++s;

  size_t count = 0;
  while (*s != '\0' && count < max) {
    while (*s == ' ' || *s == '\t' || *s == ',')
      ++s;
    if (*s == ']' || *s == '\0')
      break;
    bool neg = false;
    if (*s == '-') {
      neg = true;
      ++s;
    }
    int value = 0;
    bool any = false;
    while (*s >= '0' && *s <= '9') {
      value = value * 10 + (*s - '0');
      ++s;
      any = true;
    }
    if (!any)
      break;
    out[count++] = neg ? -value : value;
  }
  return count;
}

} // namespace Mads
