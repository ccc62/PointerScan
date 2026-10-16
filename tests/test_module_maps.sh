#!/bin/sh
set -eu
BIN=${1:-./newscan}
OUT=$("$BIN" --module-maps -p "$$" --filter libc.so 2>&1)
printf '%s\n' "$OUT" | grep -q '模块映射查询'
printf '%s\n' "$OUT" | grep -q 'libc.so'
printf '%s\n' "$OUT" | grep -q '匹配映射区域:'
if "$BIN" --module-maps >/dev/null 2>&1; then
  echo 'module maps should require a process' >&2
  exit 1
fi
echo 'module map query tests passed'
