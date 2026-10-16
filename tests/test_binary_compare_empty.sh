#!/bin/sh
# Verify that native-format empty 32-bit and 64-bit chain files are both comparable.
set -eu
BIN=${1:-./newscan}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
python3 - "$TMP" <<'PY'
import struct, sys, os
root = sys.argv[1]
for width, fmt in ((4, '<'), (8, '<')):
    header = struct.pack(fmt + '128siiii', b'.bin from chainer, by test', 0, 101, width, 0)
    for name in ('old', 'new'):
        with open(os.path.join(root, f'{name}{width}.bin'), 'wb') as f:
            f.write(header)
PY
for width in 4 8; do
  "$BIN" --compare-bin --lhs "$TMP/old${width}.bin" --rhs "$TMP/new${width}.bin" --report "$TMP/report${width}.txt" >"$TMP/run${width}.log" 2>&1
done
grep -q '旧文件总计: 0 条链' "$TMP/run4.log"
grep -q '新文件总计: 0 条链' "$TMP/run4.log"
grep -q '旧文件总计: 0 条链' "$TMP/run8.log"
grep -q '新文件总计: 0 条链' "$TMP/run8.log"
echo 'empty 32-bit and 64-bit binary compare tests passed'
