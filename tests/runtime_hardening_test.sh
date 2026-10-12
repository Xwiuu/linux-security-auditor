#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

bin_dir="$tmp_dir/bin"
mkdir -p "$bin_dir"

export PATH="$bin_dir:$PATH"

test_dnf_updates_available() {
  cat >"$bin_dir/dnf" <<'EOF'
#!/usr/bin/env bash

if [[ "$1" == "check-update" ]]; then
  printf '%s\n' 'bash.x86_64 5.3 updates'
  exit 100
fi

exit 0
EOF
  chmod +x "$bin_dir/dnf"

  source "$ROOT_DIR/modules/updates.sh"

  local output
  output="$(check_pending_updates)"

  grep -q 'UPDATE-001' <<<"$output" ||
    fail "missing UPDATE-001"

  grep -q 'Pending package updates detected' <<<"$output" ||
    fail "dnf status 100 was not handled"
}

test_dnf_failure() {
  cat >"$bin_dir/dnf" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'repository unavailable' >&2
exit 1
EOF
  chmod +x "$bin_dir/dnf"

  local output
  output="$(check_pending_updates)"

  grep -q 'could not be audited' <<<"$output" ||
    fail "dnf failure should become non-auditable"

  output="$(check_security_updates)"

  grep -q 'could not be audited' <<<"$output" ||
    fail "dnf updateinfo failure should become non-auditable"
}

test_journal_permission_denied() {
  cat >"$bin_dir/journalctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'permission denied' >&2
exit 1
EOF
  chmod +x "$bin_dir/journalctl"

  source "$ROOT_DIR/parsers/journal.sh"

  local output
  output="$(read_auth_journal)"

  grep -q 'could not be read' <<<"$output" ||
    fail "journal failure not handled"
}

test_sshlog_journal_failure() {
  source "$ROOT_DIR/parsers/ssh_auth.sh"

  local output
  output="$(parse_ssh_auth_events)"

  grep -q 'could not be read' <<<"$output" ||
    fail "sshlog journal failure not handled"
}

test_missing_target_user() {
  cat >"$bin_dir/getent" <<'EOF'
#!/usr/bin/env bash
exit 2
EOF
  chmod +x "$bin_dir/getent"

  source "$ROOT_DIR/lib/findings.sh"
  source "$ROOT_DIR/modules/permissions.sh"

  finding_reset

  SUDO_USER=deleted-user audit_ssh_home_permissions

  [[ "$(findings_count)" -eq 2 ]] ||
    fail "expected two permission findings for unresolved home"

  [[ "$(findings_get 0 id)" == "PERM-006" ]] ||
    fail "first finding should be PERM-006"

  [[ "$(findings_get 0 severity)" == "info" ]] ||
    fail "PERM-006 should be info"

  [[ "$(findings_get 1 id)" == "PERM-007" ]] ||
    fail "second finding should be PERM-007"

  [[ "$(findings_get 1 severity)" == "info" ]] ||
    fail "PERM-007 should be info"
}

test_missing_sudoers() {
  source "$ROOT_DIR/modules/sudo.sh"

  finding_reset

  SUDOERS_FILE="$tmp_dir/missing-sudoers"
  check_sudoers_permissions

  [[ "$(findings_count)" -eq 1 ]] ||
    fail "missing sudoers should emit exactly one finding"

  [[ "$(findings_get 0 id)" == "SUDO-002" ]] ||
    fail "missing sudoers finding should be SUDO-002"

  [[ "$(findings_get 0 severity)" == "info" ]] ||
    fail "missing sudoers should be info, not high"
}

test_missing_os_release() {
  source "$ROOT_DIR/modules/host.sh"

  OS_RELEASE_FILE="$tmp_dir/missing-os-release"

  [[ "$(get_os_name)" == "Unknown" ]] ||
    fail "missing os-release should report Unknown"

  [[ "$(get_os_version)" == "Unknown" ]] ||
    fail "missing os-release version should report Unknown"
}

test_firewall_zone_failure() {
  cat >"$bin_dir/firewall-cmd" <<'EOF'
#!/usr/bin/env bash

case "$*" in
  *"--get-active-zones"*)
    printf '%s\n' 'public'
    ;;

  *"--list-all"*)
    printf '%s\n' 'permission denied' >&2
    exit 1
    ;;

  *)
    exit 0
    ;;
esac
EOF
  chmod +x "$bin_dir/firewall-cmd"

  source "$ROOT_DIR/modules/firewall.sh"

  local output
  output="$(check_active_zone_rules)"

  grep -q 'Could not inspect zone public' <<<"$output" ||
    fail "denied firewall zone should be reported, not crash"

  check_broad_port_ranges >/dev/null ||
    fail "audit should continue after a denied zone"
}

test_dnf_updates_available
test_dnf_failure
test_journal_permission_denied
test_sshlog_journal_failure
test_missing_target_user
test_missing_sudoers
test_missing_os_release
test_firewall_zone_failure

printf '%s\n' 'runtime hardening tests passed'
