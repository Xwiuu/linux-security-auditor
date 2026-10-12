#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LSA="$ROOT_DIR/lsa"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# 1. Syntax
bash -n "$LSA" || fail "lsa syntax"

# 2. Default audit == text
"$LSA" audit >"$tmp_dir/default.txt"
"$LSA" audit --format text >"$tmp_dir/text.txt"

diff -u "$tmp_dir/default.txt" "$tmp_dir/text.txt" >/dev/null ||
  fail "default audit differs from text format"

# 3. JSON validity
"$LSA" audit --format json >"$tmp_dir/audit.json"

python3 -m json.tool "$tmp_dir/audit.json" >/dev/null ||
  fail "invalid JSON output"

# 4. CSV shape
"$LSA" audit --format csv >"$tmp_dir/audit.csv"

python3 - "$tmp_dir/audit.csv" <<'PY'
import csv
import sys

with open(sys.argv[1], newline="") as f:
    rows = list(csv.reader(f))

if len(rows) != 25:
    raise SystemExit(f"expected 25 CSV rows, got {len(rows)}")

if len(rows[0]) != 8:
    raise SystemExit(f"expected 8 CSV columns, got {len(rows[0])}")
PY

# 5. --output JSON
"$LSA" audit \
  --format json \
  --output "$tmp_dir/output.json"

python3 -m json.tool "$tmp_dir/output.json" >/dev/null ||
  fail "invalid JSON file output"

# 6. --output must keep stdout empty
stdout="$(
  "$LSA" audit \
    --format json \
    --output "$tmp_dir/silent.json"
)"

[[ -z "$stdout" ]] ||
  fail "--output wrote unexpected stdout"

# 7. Invalid format must fail
if "$LSA" audit --format xml >/dev/null 2>&1; then
  fail "invalid format succeeded"
fi

# 8. Missing --format value must fail
if "$LSA" audit --format >/dev/null 2>&1; then
  fail "missing --format value succeeded"
fi

# 9. Missing --output value must fail
if "$LSA" audit --output >/dev/null 2>&1; then
  fail "missing --output value succeeded"
fi

# 10. Unknown option must fail
if "$LSA" audit --banana >/dev/null 2>&1; then
  fail "unknown audit option succeeded"
fi

printf '%s\n' 'cli tests passed'
