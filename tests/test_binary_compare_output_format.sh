#!/bin/sh
# Binary comparison can emit a native .bin chain file that can be compared again.
set -eu
BIN=${1:-./newscan}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
python3 - "$TMP" <<'PY'
import os, struct, sys
root = sys.argv[1]
for width in (4, 8):
    ptr = 'I' if width == 4 else 'Q'
    sym_fmt = '@' + ptr + '64siiii'
    dir_fmt = '@' + ptr + ptr + 'II'
    header = struct.pack('@128siiii', b'.bin from chainer, by test', 1, 101, width, 1)
    sym = struct.pack(sym_fmt, 0, b'libtest.so', 0, 1, 1, 1)
    root_dir = struct.pack(dir_fmt, 0x1000, 0, 0, 1)
    level_header = struct.pack('@iIi', 0, 1, 0)
    leaf = struct.pack(dir_fmt, 0x20, 0, 0, 0)
    blob = header + sym + root_dir + level_header + leaf
    for name in ('old', 'new'):
        with open(os.path.join(root, f'{name}{width}.bin'), 'wb') as f:
            f.write(blob)
PY
for width in 4 8; do
  "$BIN" --compare-bin --lhs "$TMP/old${width}.bin" --rhs "$TMP/new${width}.bin" \
    --report-format bin --report "$TMP/common${width}.bin" >"$TMP/compare${width}.log" 2>&1
  "$BIN" --compare-bin --lhs "$TMP/common${width}.bin" --rhs "$TMP/old${width}.bin" \
    --report "$TMP/roundtrip${width}.txt" >"$TMP/roundtrip${width}.log" 2>&1
  grep -q 'libtest.so\[1\].*0x1000.*0x20' "$TMP/roundtrip${width}.txt"
done
echo 'binary compare output format round-trip tests passed'
