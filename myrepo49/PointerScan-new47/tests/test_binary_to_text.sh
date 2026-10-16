#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./outputs/newscan}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
python3 - "$TMP/sample.bin" <<'PY'
import struct, sys
out = sys.argv[1]
ptr_size = struct.calcsize('P')
header = struct.pack('@128siiii', b'.bin from chainer, by test', 1, 101, ptr_size, 0)
if ptr_size == 8:
    sym = struct.pack('@Q64siiii', 0x1000, b'libil2cpp.so', 0x1000, 1, 1, 0)
    data = struct.pack('@QQII', 0x1010, 0, 0, 0)
elif ptr_size == 4:
    sym = struct.pack('@I64siiii', 0x1000, b'libil2cpp.so', 0x1000, 1, 1, 0)
    data = struct.pack('@IIII', 0x1010, 0, 0, 0)
else:
    raise SystemExit('unsupported host pointer width')
with open(out, 'wb') as f:
    f.write(header + sym + data)
PY
"$BIN" --convert-bin-to-txt --input "$TMP/sample.bin" --report "$TMP/result.txt" > "$TMP/run.log"
grep -Fx 'libil2cpp.so[1] + 0x10' "$TMP/result.txt"
grep -q '转换链数: 1' "$TMP/run.log"
printf 'bad' > "$TMP/bad.bin"
if "$BIN" --convert-bin-to-txt --input "$TMP/bad.bin" --report "$TMP/bad.txt" >/dev/null 2>&1; then
  echo 'invalid binary was unexpectedly accepted' >&2
  exit 1
fi
echo 'binary-to-text conversion tests passed.'
