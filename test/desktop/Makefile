# Desktop test harness for MadsUnoAgent.
#
# Builds src/mads/*.cpp against a POSIX-socket stand-in for WiFiS3.h
# (arduino_stub/), so the library's actual production sources run under
# ASan/UBSan on the desktop instead of against an emulator.
#
# Usage: see README.md. Quick start:
#   ARDUINOJSON_DIR=/path/to/ArduinoJson/src make test
#
# test_crypto_vectors/test_entropy (Phase 2/3) always build with
# MADS_ENABLE_CURVE themselves once their sources exist -- there is nothing
# to test in them otherwise. MADS_ENABLE_CURVE=1 passed to `make` instead
# additionally compiles test_toml_scan/test_zmtp_null (the NULL-mechanism
# library tests) with -DMADS_ENABLE_CURVE, to catch anything in
# mads_agent.cpp/zmtp_session.cpp that only compiles under one of the two
# modes.

CXX ?= g++
STD := -std=c++17
WARN := -Wall -Wextra
SAN := -fsanitize=address,undefined -fno-omit-frame-pointer
OPT := -g -O0

SRC_DIR := ../../src/mads
STUB_DIR := arduino_stub

# ArduinoJson is a real dependency (mads_agent.hpp includes <ArduinoJson.h>).
# Point this at the library's src/ directory (the one containing
# ArduinoJson.h) -- e.g. wherever `arduino-cli lib install ArduinoJson`, or a
# manual clone of https://github.com/bblanchon/ArduinoJson, put it.
ARDUINOJSON_DIR ?=

ifeq ($(ARDUINOJSON_DIR),)
$(warning ARDUINOJSON_DIR is not set -- pass it on the command line, e.g. \
  `make test ARDUINOJSON_DIR=/path/to/ArduinoJson/src`. Falling back to \
  /usr/include/ArduinoJson, which almost certainly does not exist.)
ARDUINOJSON_DIR := /usr/include/ArduinoJson
endif

INCLUDES := -I$(STUB_DIR) -I$(SRC_DIR) -isystem $(ARDUINOJSON_DIR)

ifdef MADS_ENABLE_CURVE
CURVE_DEFS := -DMADS_ENABLE_CURVE
else
CURVE_DEFS :=
endif

CXXFLAGS := $(STD) $(WARN) $(SAN) $(OPT) $(INCLUDES) $(CURVE_DEFS)
LDFLAGS  := $(SAN)

BUILD := build
$(shell mkdir -p $(BUILD))

# ---------------------------------------------------------------------------
# test_toml_scan -- pure unit tests, no Arduino stub, no network.
# ---------------------------------------------------------------------------
TOML_SRCS := test_toml_scan.cpp $(SRC_DIR)/toml_scan.cpp
TOML_BIN  := $(BUILD)/test_toml_scan

$(TOML_BIN): $(TOML_SRCS) $(SRC_DIR)/toml_scan.hpp
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR)/.. $(TOML_SRCS) -o $@ $(LDFLAGS)

# ---------------------------------------------------------------------------
# test_zmtp_null -- live test against a real broker; the binary always
# builds, but skips cleanly at runtime unless MADS_BROKER_HOST is set.
# ---------------------------------------------------------------------------
AGENT_SESSION_SRC := $(wildcard $(SRC_DIR)/zmtp_session.cpp)
ifeq ($(AGENT_SESSION_SRC),)
AGENT_SESSION_SRC := $(SRC_DIR)/zmtp_codec.cpp
endif

ZMTP_SRCS := test_zmtp_null.cpp $(SRC_DIR)/mads_agent.cpp \
             $(SRC_DIR)/toml_scan.cpp $(AGENT_SESSION_SRC) \
             $(STUB_DIR)/WiFiS3.cpp
ZMTP_BIN  := $(BUILD)/test_zmtp_null

$(ZMTP_BIN): $(ZMTP_SRCS)
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR)/.. $(ZMTP_SRCS) -o $@ $(LDFLAGS)

# ---------------------------------------------------------------------------
# test_crypto_vectors -- Phase 2, guarded: only built when the crypto/
# sources exist (they are added in Phase 2, kept out of the Phase 0/1 tree).
# ---------------------------------------------------------------------------
CRYPTO_DIR := $(SRC_DIR)/crypto
CRYPTO_TEST_SRC := test_crypto_vectors.cpp
CRYPTO_BIN := $(BUILD)/test_crypto_vectors
HAVE_CRYPTO_TEST := $(wildcard $(CRYPTO_TEST_SRC))

ifneq ($(HAVE_CRYPTO_TEST),)
CRYPTO_SRCS := $(CRYPTO_TEST_SRC) \
               $(CRYPTO_DIR)/salsa20.cpp \
               $(CRYPTO_DIR)/nacl_box.cpp \
               $(CRYPTO_DIR)/monocypher_unit.c

$(CRYPTO_BIN): $(CRYPTO_SRCS)
	$(CXX) $(CXXFLAGS) -DMADS_ENABLE_CURVE -I$(CRYPTO_DIR) \
	  -c test_crypto_vectors.cpp -o $(BUILD)/test_crypto_vectors.o
	$(CXX) $(CXXFLAGS) -DMADS_ENABLE_CURVE -I$(CRYPTO_DIR) \
	  -c $(CRYPTO_DIR)/salsa20.cpp -o $(BUILD)/salsa20.o
	$(CXX) $(CXXFLAGS) -DMADS_ENABLE_CURVE -I$(CRYPTO_DIR) \
	  -c $(CRYPTO_DIR)/nacl_box.cpp -o $(BUILD)/nacl_box.o
	$(CC) -std=c99 -Wall -O0 -g $(SAN) -DMADS_ENABLE_CURVE \
	  -c $(CRYPTO_DIR)/monocypher_unit.c -o $(BUILD)/monocypher_unit.o
	$(CXX) $(LDFLAGS) $(BUILD)/test_crypto_vectors.o $(BUILD)/salsa20.o \
	  $(BUILD)/nacl_box.o $(BUILD)/monocypher_unit.o -o $(CRYPTO_BIN)
endif

# ---------------------------------------------------------------------------
# test_entropy -- Phase 3, guarded the same way. Two binaries from the same
# source: the real desktop backend (smoke test), and the deterministic test
# hook (its determinism can only be shown by two separate process
# invocations producing the same output -- see the `test` target below and
# test_entropy.cpp's file comment).
# ---------------------------------------------------------------------------
ENTROPY_TEST_SRC := test_entropy.cpp
ENTROPY_BIN := $(BUILD)/test_entropy
ENTROPY_DETERM_BIN := $(BUILD)/test_entropy_deterministic
HAVE_ENTROPY_TEST := $(wildcard $(ENTROPY_TEST_SRC))

ifneq ($(HAVE_ENTROPY_TEST),)
$(ENTROPY_BIN): test_entropy.cpp $(SRC_DIR)/entropy_desktop.cpp $(SRC_DIR)/entropy.hpp
	$(CXX) $(CXXFLAGS) -DMADS_ENABLE_CURVE \
	  -I$(SRC_DIR) test_entropy.cpp $(SRC_DIR)/entropy_desktop.cpp \
	  -o $@ $(LDFLAGS)

$(ENTROPY_DETERM_BIN): test_entropy.cpp $(SRC_DIR)/entropy_desktop.cpp $(SRC_DIR)/entropy.hpp
	$(CXX) $(CXXFLAGS) -DMADS_ENABLE_CURVE -DMADS_CURVE_TEST_ENTROPY \
	  -I$(SRC_DIR) test_entropy.cpp $(SRC_DIR)/entropy_desktop.cpp \
	  -o $@ $(LDFLAGS)
endif

# ---------------------------------------------------------------------------
# Top-level targets
# ---------------------------------------------------------------------------
.PHONY: all test clean stackreport

all: $(TOML_BIN) $(ZMTP_BIN) $(if $(HAVE_CRYPTO_TEST),$(CRYPTO_BIN)) $(if $(HAVE_ENTROPY_TEST),$(ENTROPY_BIN) $(ENTROPY_DETERM_BIN))

test: all
	@echo "--- test_toml_scan ---"
	$(TOML_BIN)
	@echo "--- test_zmtp_null ---"
	$(ZMTP_BIN)
ifneq ($(HAVE_CRYPTO_TEST),)
	@echo "--- test_crypto_vectors ---"
	$(CRYPTO_BIN)
endif
ifneq ($(HAVE_ENTROPY_TEST),)
	@echo "--- test_entropy (desktop backend smoke test) ---"
	$(ENTROPY_BIN)
	@echo "--- test_entropy_deterministic (two independent process runs must match) ---"
	$(ENTROPY_DETERM_BIN) > $(BUILD)/entropy_run1.hex
	$(ENTROPY_DETERM_BIN) > $(BUILD)/entropy_run2.hex
	@if diff -q $(BUILD)/entropy_run1.hex $(BUILD)/entropy_run2.hex >/dev/null; then \
	  echo "test_entropy_deterministic: PASSED ($$(cat $(BUILD)/entropy_run1.hex))"; \
	else \
	  echo "test_entropy_deterministic: FAILED -- two runs produced different output"; \
	  exit 1; \
	fi
endif

# ---------------------------------------------------------------------------
# stackreport -- deepest call-chain stack usage through the library sources,
# via -fstack-usage + a call-graph walk (see stackreport.py). Needed from
# Phase 3 onward (entropy backends) and mandatory once curve_handshake exists
# (Phase 4+, out of this pass's scope) to prove the 512-byte budget in
# CURVE_PLAN.md Sec 7.2.
# ---------------------------------------------------------------------------
STACKREPORT_SRCS := $(wildcard $(SRC_DIR)/*.cpp) $(wildcard $(SRC_DIR)/crypto/*.cpp)
STACKREPORT_BUILD := $(BUILD)/stackreport

stackreport:
	@mkdir -p $(STACKREPORT_BUILD)
	@for f in $(STACKREPORT_SRCS); do \
	  base=$$(basename $$f .cpp); \
	  $(CXX) $(STD) $(WARN) -O1 -fstack-usage -DMADS_ENABLE_CURVE \
	    $(INCLUDES) -I$(SRC_DIR)/.. -I$(SRC_DIR)/crypto \
	    -c $$f -o $(STACKREPORT_BUILD)/$$base.o \
	    2>/dev/null || true; \
	  mv -f $$base.su $(STACKREPORT_BUILD)/ 2>/dev/null || true; \
	done
	@python3 stackreport.py $(STACKREPORT_BUILD)

clean:
	rm -rf $(BUILD) *.su
