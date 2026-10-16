#!/bin/sh
# Integration smoke test: the binary comparator must accept valid empty native-format files.
set -eu
BIN=${1:-./newscan}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
python3 - "$TMP/old.bin" "$TMP/new.bin" <<'PY'
import struct, sys
header = struct.pack('<128siiii', b'.bin from chainer, by test', 0, 101, struct.calcsize('P'), 0)
for path in sys.argv[1:]:
    with open(path, 'wb') as f:
        f.write(header)
PY
"$BIN" --compare-bin --lhs "$TMP/old.bin" --rhs "$TMP/new.bin" --report "$TMP/report.txt" >"$TMP/run.log" 2>&1
grep -q '旧文件总计: 0 条链' "$TMP/run.log"
grep -q '新文件总计: 0 条链' "$TMP/run.log"
grep -q '对比报告已保存至:' "$TMP/run.log"
echo 'empty binary compare test passed'
