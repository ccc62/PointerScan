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
libil2cpp.so[1]:bss + 0x80B0 -> + 0x738 -> + 0xBE0 -> + 0x260 -> + 0x874
CHAINS

cat > "$TMP/new.txt" <<'CHAINS'
libil2cpp.so[1] + 0x1B60E88 -> + 0xFD0 -> + 0x934
libil2cpp.so:bss[1] + 0x25648 -> + 0x200 -> + 0x874
libNetHTProtect.so:bss[1] + 0x53D78 -> + 0xAF8 -> + 0x5F8 -> + 0x874
libil2cpp.so[1] + 0x25648 -> + 0x200 -> + 0x874
libil2cpp.so:bss[1] + 0x80B0 -> + 0x738 -> + 0xBE0 -> + 0x260 -> + 0x874
libil2cpp.so:bss[1] + 0x80B0 -> + 0x738 -> + 0xBE0 -> + 0x280 -> + 0x874
libil2cpp.so:bss[1] + 0x25648 -> + 0x200 -> + 0x874
CHAINS

"$BIN" --compare-txt --lhs "$TMP/old.txt" --rhs "$TMP/new.txt" --report "$TMP/report.txt"

# Both spellings of the BSS marker must compare as the same BSS chain.
test "$(grep -Fxc 'libil2cpp.so[1]:bss + 0x25648 -> + 0x200 -> + 0x874' "$TMP/report.txt")" -eq 1
test "$(grep -Fxc 'libNetHTProtect.so[1]:bss + 0x53D78 -> + 0xAF8 -> + 0x5F8 -> + 0x874' "$TMP/report.txt")" -eq 1
# Normal mapping and BSS mapping remain distinct identities.
test "$(grep -Fxc 'libil2cpp.so[1] + 0x25648 -> + 0x200 -> + 0x874' "$TMP/report.txt")" -eq 1
# Exact offset path matches; the 0x280 variant must not match the 0x260 path.
test "$(grep -Fxc 'libil2cpp.so[1]:bss + 0x80B0 -> + 0x738 -> + 0xBE0 -> + 0x260 -> + 0x874' "$TMP/report.txt")" -eq 1
test "$(grep -F '0x280' "$TMP/report.txt" | wc -l | tr -d ' ')" -eq 0
# Duplicate rhs rows must not duplicate report rows.
test "$(wc -l < "$TMP/report.txt" | tr -d ' ')" -eq 5

echo 'Text compare format tests passed.'
