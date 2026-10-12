#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$ROOT_DIR/lib/findings.sh"
source "$ROOT_DIR/reporters/text.sh"

failures=0

pass() {
  printf 'ok   - %s\n' "$1"
}

fail() {
  printf 'FAIL - %s\n' "$1"
  failures=$(( failures + 1 ))
}

assert_eq() {
  local expected="$1"
  local actual="$2"
  local label="$3"

  if [[ "$expected" == "$actual" ]]; then
    pass "$label"
  else
    fail "$label (expected [$expected], got [$actual])"
  fi
}


index=0
for field in "${LSA_FINDING_FIELDS[@]}"; do
  assert_eq "$index" "$(finding_field_offset "$field")" "offset of $field is $index"
  index=$(( index + 1 ))
done

assert_eq "8" "${#LSA_FINDING_FIELDS[@]}" "finding has 8 fields"

finding id=T-001 category=test severity=pass title="All good" >/dev/null
finding id=T-002 category=test severity=critical title="Broken" >/dev/null
finding id=T-003 category=test severity=medium title="Custom" >/dev/null

assert_eq "3" "$(findings_count)" "finding stores without printing"
assert_eq "" "$(finding id=T-004 category=test severity=low title="silent")" \
  "finding returns no output"

assert_eq "PASS" \
  "$(finding_severity_tag "$(findings_get 0 severity)")" \
  "tags severity pass as PASS"

assert_eq "CRITICAL" \
  "$(finding_severity_tag "$(findings_get 1 severity)")" \
  "tags severity critical as CRITICAL"

assert_eq "MEDIUM" \
  "$(finding_severity_tag "$(findings_get 2 severity)")" \
  "tags severity medium as MEDIUM"

report="$(render_text_findings)"
case "$report" in
  "[PASS] T-001"$'\n''All good'*)
    pass "render_text_findings opens with the first finding block"
    ;;
  *)
    fail "render_text_findings opens with the first finding block (got [${report%%$'\n'*}])"
    ;;
esac

case "$report" in
  *'[CRITICAL] T-002'$'\n''Broken'*)
    pass "render_text_findings prints later findings"
    ;;
  *)
    fail "render_text_findings prints later findings"
    ;;
esac

finding_reset
assert_eq "0" "$(findings_count)" "count is 0 after reset"

finding id=FIRST category=test severity=warn title="first title" \
  description="first description" expected="first expected" \
  actual="first actual" recommendation="first recommendation" >/dev/null

assert_eq "1" "$(findings_count)" "count is 1 after one finding"
assert_eq "FIRST" "$(findings_get 0 id)" "reads id"
assert_eq "test" "$(findings_get 0 category)" "reads category"
assert_eq "warn" "$(findings_get 0 severity)" "reads severity"
assert_eq "first title" "$(findings_get 0 title)" "reads title"
assert_eq "first description" "$(findings_get 0 description)" "reads description"
assert_eq "first expected" "$(findings_get 0 expected)" "reads expected"
assert_eq "first actual" "$(findings_get 0 actual)" "reads actual"
assert_eq "first recommendation" "$(findings_get 0 recommendation)" "reads recommendation"

finding id=SECOND category=test severity=info title="second title" \
  recommendation="second recommendation" >/dev/null

assert_eq "2" "$(findings_count)" "count is 2 after two findings"
assert_eq "first recommendation" "$(findings_get 0 recommendation)" "field isolation on index 0"
assert_eq "second recommendation" "$(findings_get 1 recommendation)" "field isolation on index 1"
assert_eq "" "$(findings_get 1 description)" "unset field returns empty"

finding_reset
finding id=SUM-001 severity=pass title="a" >/dev/null
finding id=SUM-002 severity=warn title="b" >/dev/null
finding id=SUM-003 severity=high title="c" >/dev/null

assert_eq "Findings: 3 total (1 pass, 0 info, 0 low, 0 medium, 1 warn, 1 high, 0 critical)" \
  "$(findings_summary)" "summary counts by severity"

assert_eq "0" "$(finding_severity_rank pass)" "rank of pass"
assert_eq "4" "$(finding_severity_rank warn)" "rank of warn"
assert_eq "6" "$(finding_severity_rank critical)" "rank of critical"

if finding title="missing id" >/dev/null 2>&1; then
  fail "rejects a finding without id="
else
  pass "rejects a finding without id="
fi

if finding id=T-004 >/dev/null 2>&1; then
  fail "rejects a finding without title="
else
  pass "rejects a finding without title="
fi

if finding id=T-005 unknown=value >/dev/null 2>&1; then
  fail "rejects an unknown field"
else
  pass "rejects an unknown field"
fi

if findings_get 0 unknown_field >/dev/null 2>&1; then
  fail "findings_get rejects an unknown field"
else
  pass "findings_get rejects an unknown field"
fi

source "$ROOT_DIR/modules/ssh.sh"

finding_reset

check_sshd_available

assert_eq "1" "$(findings_count)" "ssh module stored its finding"
assert_eq "SSH-001" "$(findings_get 0 id)" "ssh module stored id"
assert_eq "ssh" "$(findings_get 0 category)" "ssh module stored category"

ssh_severity="$(findings_get 0 severity)"
case "$ssh_severity" in
  pass|info)
    pass "ssh module emits a finding through the engine"
    ;;
  *)
    fail "ssh module emits a finding through the engine (severity [$ssh_severity])"
    ;;
esac

ssh_report="$(render_text_findings)"
case "$ssh_report" in
  "[${ssh_severity^^}] SSH-001"$'\n'*)
    pass "ssh module finding renders through the reporter"
    ;;
  *)
    fail "ssh module finding renders through the reporter (got [${ssh_report%%$'\n'*}])"
    ;;
esac

finding_reset

if (( failures > 0 )); then
  printf '\n%d test(s) failed\n' "$failures"
  exit 1
fi

printf '\nall tests passed\n'
