// Pure unit tests for TomlScan -- no network, no board. Exercises the
// streaming line-by-line scanner against synthetic settings-reply text,
// including the awkward cases: chunked feed() boundaries splitting a line
// mid-key, a missing trailing newline, reset() between two runs, and the
// `[agents]` + watched-section interaction fetch_settings() depends on.
#include "toml_scan.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>

using Mads::TomlScan;

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    ++g_checks;                                                              \
    if (!(cond)) {                                                           \
      ++g_failures;                                                          \
      std::fprintf(stderr, "CHECK FAILED: %s (%s:%d)\n", #cond, __FILE__,    \
                    __LINE__);                                               \
    }                                                                        \
  } while (0)

static const char *kSampleIni =
    "# comment line, must be ignored\n"
    "[agents]\n"
    "frontend_address = \"tcp://*:9090\"\n"
    "backend_address = \"tcp://*:9091\"\n"
    "timecode_fps = 25\n"
    "\n"
    "[uno_r4]\n"
    "ai = [0, 2, 4]\n"
    "di = [1, 3]\n"
    "delay = 100\n"
    "note = \"  padded value  \"\n";

static void test_basic_scan() {
  TomlScan scan;
  scan.watch_section("uno_r4");
  scan.feed(reinterpret_cast<const uint8_t *>(kSampleIni), strlen(kSampleIni));
  scan.finish();

  CHECK(scan.done());
  CHECK(scan.frontend_port() == 9090);
  CHECK(scan.backend_port() == 9091);
  CHECK(scan.timecode_fps() == 25);

  CHECK(scan.int_value("delay", -1) == 100);
  CHECK(scan.int_value("missing_key", 42) == 42);

  int arr[8] = {0};
  size_t n = scan.int_array("ai", arr, 8);
  CHECK(n == 3);
  CHECK(arr[0] == 0 && arr[1] == 2 && arr[2] == 4);

  n = scan.int_array("di", arr, 8);
  CHECK(n == 2);
  CHECK(arr[0] == 1 && arr[1] == 3);

  // TomlScan captures raw text verbatim (only whitespace *outside* the
  // value's own content is trimmed) -- it does not strip quotes or collapse
  // internal whitespace, so the quotes and the padding inside them survive.
  const char *note = scan.raw_value("note");
  CHECK(note != nullptr);
  CHECK(strcmp(note, "\"  padded value  \"") == 0);
}

// fetch_settings() feeds the ini text in small, arbitrary-sized chunks off
// the wire (32-byte reads in the pre-CURVE code, a variable-sized streaming
// chunk once ZmtpSession owns it) -- verify the scanner is agnostic to where
// chunk boundaries fall, including mid-key and mid-number splits.
static void test_chunked_feed_matches_whole_feed() {
  TomlScan whole;
  whole.watch_section("uno_r4");
  whole.feed(reinterpret_cast<const uint8_t *>(kSampleIni), strlen(kSampleIni));
  whole.finish();

  for (size_t chunk = 1; chunk <= 7; ++chunk) {
    TomlScan chunked;
    chunked.watch_section("uno_r4");
    size_t len = strlen(kSampleIni);
    for (size_t i = 0; i < len; i += chunk) {
      size_t n = (i + chunk > len) ? (len - i) : chunk;
      chunked.feed(reinterpret_cast<const uint8_t *>(kSampleIni + i), n);
    }
    chunked.finish();

    CHECK(chunked.done() == whole.done());
    CHECK(chunked.frontend_port() == whole.frontend_port());
    CHECK(chunked.backend_port() == whole.backend_port());
    CHECK(chunked.timecode_fps() == whole.timecode_fps());
    CHECK(chunked.int_value("delay", -1) == whole.int_value("delay", -1));
  }
}

// No trailing '\n' after the last line -- finish() must still flush it.
static void test_missing_trailing_newline() {
  TomlScan scan;
  scan.watch_section("uno_r4");
  const char *text = "[agents]\n"
                      "frontend_address = \"tcp://*:9090\"\n"
                      "backend_address = \"tcp://*:9091\"\n"
                      "timecode_fps = 25";
  scan.feed(reinterpret_cast<const uint8_t *>(text), strlen(text));
  // Without finish(), the last line ("timecode_fps = 25") is still sitting
  // in the line buffer and must NOT have been processed yet.
  CHECK(!scan.done());
  scan.finish();
  CHECK(scan.done());
  CHECK(scan.timecode_fps() == 25);
}

// reset() must fully clear state -- a second run must not see a stale
// done()==true, leftover port numbers, or duplicated watched-section
// entries appended on top of the first run's.
static void test_reset_clears_state() {
  TomlScan scan;
  scan.watch_section("uno_r4");
  scan.feed(reinterpret_cast<const uint8_t *>(kSampleIni), strlen(kSampleIni));
  scan.finish();
  CHECK(scan.done());

  scan.reset();
  CHECK(!scan.done());
  CHECK(scan.frontend_port() == 0);
  CHECK(scan.backend_port() == 0);
  CHECK(scan.timecode_fps() == 0);
  CHECK(scan.raw_value("delay") == nullptr);

  // Feed a *different* reply and check no ghosts from run 1 leak through.
  const char *text2 = "[agents]\n"
                       "frontend_address = \"tcp://*:7000\"\n"
                       "backend_address = \"tcp://*:7001\"\n"
                       "timecode_fps = 30\n"
                       "[uno_r4]\n"
                       "delay = 5\n";
  scan.feed(reinterpret_cast<const uint8_t *>(text2), strlen(text2));
  scan.finish();
  CHECK(scan.done());
  CHECK(scan.frontend_port() == 7000);
  CHECK(scan.backend_port() == 7001);
  CHECK(scan.timecode_fps() == 30);
  CHECK(scan.int_value("delay", -1) == 5);

  int arr[4];
  CHECK(scan.int_array("ai", arr, 4) == 0); // "ai" belonged to run 1 only
}

// A section other than the watched one, and lines outside any section, must
// not be captured.
static void test_unwatched_section_ignored() {
  TomlScan scan;
  scan.watch_section("uno_r4");
  const char *text = "top_level = 1\n"
                      "[other_agent]\n"
                      "ai = [9, 9]\n"
                      "[agents]\n"
                      "frontend_address = \"tcp://*:9090\"\n"
                      "backend_address = \"tcp://*:9091\"\n"
                      "timecode_fps = 25\n";
  scan.feed(reinterpret_cast<const uint8_t *>(text), strlen(text));
  scan.finish();
  CHECK(scan.done());
  CHECK(scan.raw_value("top_level") == nullptr);
  CHECK(scan.raw_value("ai") == nullptr);
}

int main() {
  test_basic_scan();
  test_chunked_feed_matches_whole_feed();
  test_missing_trailing_newline();
  test_reset_clears_state();
  test_unwatched_section_ignored();

  std::printf("test_toml_scan: %d checks, %d failures\n", g_checks,
              g_failures);
  return g_failures == 0 ? 0 : 1;
}
