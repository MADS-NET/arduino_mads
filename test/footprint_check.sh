#!/usr/bin/env bash
# CURVE_PLAN.md Phase 7: build gating and footprint proof, as a repeatable
# check rather than a set of numbers someone once pasted into a commit.
#
# Proves two things:
#   1. The disabled build contains NO crypto. This is the property Sec 7.3
#      actually cares about -- a byte count is only a proxy for it, and a
#      proxy that goes stale the moment anything else in the library moves.
#   2. The enabled build works and costs what we say it costs.
#
# Usage:  test/footprint_check.sh [--verbose]
# Exit:   0 if the disabled builds are crypto-free, 1 otherwise.
set -u

FQBN=arduino:renesas_uno:unor4wifi
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CURVE_FLAG='build.extra_flags=-DMADS_ENABLE_CURVE'
# Any of these appearing in a disabled build means crypto leaked into it.
LEAK_RE='x25519|monocypher|salsa|poly1305|secretbox|curve_handshake|z85'

NM="$(find "$HOME/Library/Arduino15/packages/arduino/tools/arm-none-eabi-gcc" \
        -name 'arm-none-eabi-nm' -type f 2>/dev/null | head -1)"
if [ -z "$NM" ]; then
  echo "footprint_check: arm-none-eabi-nm not found; install the UNO R4 core." >&2
  exit 1
fi

tmp="$REPO/.footprint_build"
mkdir -p "$tmp"
trap 'rm -rf "$tmp"' EXIT
fail=0

# build <sketch> <enabled:0|1> -> prints "flash ram", leaves the elf in $tmp/bp
build() {
  local sketch="$1" enabled="$2"
  rm -rf "$tmp/bp"
  local out
  if [ "$enabled" = 1 ]; then
    out="$(arduino-cli compile --fqbn "$FQBN" --library "$REPO" \
             --build-path "$tmp/bp" --build-property "$CURVE_FLAG" \
             "$REPO/examples/$sketch" 2>&1)"
  else
    out="$(arduino-cli compile --fqbn "$FQBN" --library "$REPO" \
             --build-path "$tmp/bp" "$REPO/examples/$sketch" 2>&1)"
  fi
  if ! printf '%s' "$out" | grep -q 'Sketch uses'; then
    printf '%s\n' "$out" >&2
    return 1
  fi
  printf '%s' "$out" | awk '
    /Sketch uses/          { gsub(/[^0-9]/,"",$3); f=$3 }
    /Global variables use/ { gsub(/[^0-9]/,"",$4); r=$4 }
    END { print f, r }'
}

crypto_syms() { "$NM" "$tmp"/bp/*.elf 2>/dev/null | grep -Eic "$LEAK_RE"; }

printf '%-16s %-9s %8s %8s %8s\n' sketch CURVE flash RAM crypto-syms
printf '%-16s %-9s %8s %8s %8s\n' ---------------- --------- -------- -------- -----------

for sketch in minimal_pub pub_sub uno_r4_sensor; do
  read -r flash ram <<<"$(build "$sketch" 0)" || { echo "build failed: $sketch" >&2; fail=1; continue; }
  n="$(crypto_syms)"
  printf '%-16s %-9s %8s %8s %8s' "$sketch" disabled "$flash" "$ram" "$n"
  if [ "$n" -ne 0 ]; then printf '  <-- LEAK\n'; fail=1; else printf '\n'; fi
done

if [ -d "$REPO/examples/crypto_pub" ]; then
  if [ -f "$REPO/examples/crypto_pub/arduino_secrets.h" ]; then
    read -r dflash dram <<<"$(build crypto_pub 0)" || fail=1
    dn="$(crypto_syms)"
    printf '%-16s %-9s %8s %8s %8s' crypto_pub disabled "$dflash" "$dram" "$dn"
    if [ "$dn" -ne 0 ]; then printf '  <-- LEAK\n'; fail=1; else printf '\n'; fi

    read -r eflash eram <<<"$(build crypto_pub 1)" || fail=1
    en="$(crypto_syms)"
    printf '%-16s %-9s %8s %8s %8s\n' crypto_pub enabled "$eflash" "$eram" "$en"
    if [ "$en" -eq 0 ]; then
      echo "  ERROR: the enabled build has no crypto symbols -- the flag did not take." >&2
      fail=1
    fi
    echo
    echo "CURVE cost, same sketch both ways:"
    printf '  flash %+d B (%.1f KB)   RAM %+d B\n' \
      "$((eflash - dflash))" \
      "$(awk -v a="$eflash" -v b="$dflash" 'BEGIN{printf "%.1f", (a-b)/1024}')" \
      "$((eram - dram))"
  else
    echo
    echo "(crypto_pub skipped: needs examples/crypto_pub/arduino_secrets.h --"
    echo " copy arduino_secrets.h.example and fill in keys. It is gitignored.)"
  fi
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "PASS: no crypto symbols in any disabled build."
else
  echo "FAIL: see above."
fi
exit "$fail"
