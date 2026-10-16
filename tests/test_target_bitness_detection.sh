#!/bin/sh
# Use this shell process as a harmless target to smoke-test ELF-class detection.
set -eu
BIN=${1:-./newscan}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
: > "$TMP/chains.txt"
"$BIN" --locate-address -p "$$" --chains "$TMP/chains.txt" --target-address 1 --file "$TMP/hits.txt" > "$TMP/run.log"
grep -Eq '目标指针宽度: (32|64) 位' "$TMP/run.log"
echo 'target ELF bitness detection smoke test passed'
