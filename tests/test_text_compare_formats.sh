#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./outputs/newscan}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/old.txt" <<'CHAINS'
libil2cpp.so[1] + 0x1B60E88 -> + 0xFD0 -> + 0x934
libil2cpp.so[1]:bss + 0x25648 -> + 0x200 -> + 0x874
libNetHTProtect.so[1]:bss + 0x53D78 -> + 0xAF8 -> + 0x5F8 -> + 0x874
libil2cpp.so[1] + 0x25648 -> + 0x200 -> + 0x874
CHAINS

cat > "$TMP/new.txt" <<'CHAINS'
libil2cpp.so[1] + 0x1B60E88 -> + 0xFD0 -> + 0x934
libil2cpp.so[1]:bss + 0x25648 -> + 0x200 -> + 0x874
libNetHTProtect.so[1]:bss + 0x53D78 -> + 0xAF8 -> + 0x5F8 -> + 0x874
libil2cpp.so[1] + 0x25648 -> + 0x200 -> + 0x874
libil2cpp.so[1]:bss + 0x25648 -> + 0x200 -> + 0x874
CHAINS

"$BIN" --compare-txt --lhs "$TMP/old.txt" --rhs "$TMP/new.txt" --report "$TMP/report.txt"

# Both ordinary and :bss versions must be preserved as distinct identities.
test "$(grep -Fxc 'libil2cpp.so[1]:bss + 0x25648 -> + 0x200 -> + 0x874' "$TMP/report.txt")" -eq 1
test "$(grep -Fxc 'libil2cpp.so[1] + 0x25648 -> + 0x200 -> + 0x874' "$TMP/report.txt")" -eq 1
# Duplicate rhs rows must not duplicate report rows.
test "$(wc -l < "$TMP/report.txt" | tr -d ' ')" -eq 4

echo 'Text compare format tests passed.'
