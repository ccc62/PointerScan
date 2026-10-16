#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./outputs/newscan}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
python3 - "$TMP" <<'PY'
import struct, sys, os
root = sys.argv[1]
for ptr_size in (4, 8):
    header = struct.pack('@128siiii', b'.bin from chainer, by test', 1, 101, ptr_size, 0)
    if ptr_size == 8:
        sym = struct.pack('@Q64siiii', 0x1000, b'libil2cpp.so', 0x1000, 1, 1, 0)
        data = struct.pack('@QQII', 0x1010, 0, 0, 0)
    else:
        sym = struct.pack('@I64siiii', 0x1000, b'libil2cpp.so', 0x1000, 1, 1, 0)
        data = struct.pack('@IIII', 0x1010, 0, 0, 0)
    with open(os.path.join(root, f'sample{ptr_size}.bin'), 'wb') as f:
        f.write(header + sym + data)
PY
for width in 4 8; do
  "$BIN" --convert-bin-to-txt --input "$TMP/sample${width}.bin" --report "$TMP/result${width}.txt" > "$TMP/run${width}.log"
  grep -Fx 'libil2cpp.so[1] + 0x10' "$TMP/result${width}.txt"
  grep -q '转换链数: 1' "$TMP/run${width}.log"
done
printf 'bad' > "$TMP/bad.bin"
if "$BIN" --convert-bin-to-txt --input "$TMP/bad.bin" --report "$TMP/bad.txt" >/dev/null 2>&1; then
  echo 'invalid binary was unexpectedly accepted' >&2
  exit 1
fi
echo '32-bit and 64-bit binary-to-text conversion tests passed.'
