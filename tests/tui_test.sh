#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

source "$ROOT_DIR/lib/findings.sh"
source "$ROOT_DIR/reporters/text.sh"
source "$ROOT_DIR/reporters/json.sh"
source "$ROOT_DIR/reporters/csv.sh"
source "$ROOT_DIR/tui/main.sh"

bash -n "$ROOT_DIR/tui/main.sh" ||
  fail "tui syntax"

# Header
header="$(tui_header)"

grep -q 'Linux Security Auditor' <<< "$header" ||
  fail "missing TUI title"

# No findings path
finding_reset

output="$(tui_view_findings)"

grep -q 'No findings loaded.' <<< "$output" ||
  fail "empty findings state missing"

# Export without findings
output="$(
  printf '1\n' | tui_export_report
)"

grep -q 'No findings loaded.' <<< "$output" ||
  fail "export without findings should be blocked"

printf '%s\n' 'tui tests passed'
