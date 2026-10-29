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

  source "$ROOT_DIR/lib/findings.sh"
  source "$ROOT_DIR/modules/updates.sh"

  finding_reset

  local out_file="$tmp_dir/dnf-available.out"
  check_pending_updates >"$out_file"

  [[ ! -s "$out_file" ]] ||
    fail "check_pending_updates should store findings, not print"

  [[ "$(findings_count)" -eq 1 ]] ||
    fail "status 100 should emit one finding"

  [[ "$(findings_get 0 id)" == "UPDATE-001" ]] ||
    fail "finding id should be UPDATE-001"

  [[ "$(findings_get 0 severity)" == "info" ]] ||
    fail "status 100 should be info"
}

test_dnf_failure() {
  cat >"$bin_dir/dnf" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'repository unavailable' >&2
exit 1
EOF
  chmod +x "$bin_dir/dnf"

  finding_reset

  local out_file="$tmp_dir/dnf-fail.out"
  check_pending_updates >"$out_file"

  [[ ! -s "$out_file" ]] ||
    fail "check_pending_updates should store findings, not print"

  [[ "$(findings_count)" -eq 1 ]] ||
    fail "dnf failure should emit one UPDATE-001 finding"

  [[ "$(findings_get 0 id)" == "UPDATE-001" ]] ||
    fail "failed check should keep UPDATE-001"

  [[ "$(findings_get 0 severity)" == "info" ]] ||
    fail "dnf failure should be info, not high"

  finding_reset

  out_file="$tmp_dir/dnf-updateinfo-fail.out"
  check_security_updates >"$out_file"

  [[ ! -s "$out_file" ]] ||
    fail "check_security_updates should store findings, not print"

  [[ "$(findings_count)" -eq 1 ]] ||
    fail "dnf updateinfo failure should emit one UPDATE-002 finding"

  [[ "$(findings_get 0 id)" == "UPDATE-002" ]] ||
    fail "failed security check should keep UPDATE-002"

  [[ "$(findings_get 0 severity)" == "info" ]] ||
    fail "updateinfo failure should be info, not high"
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

  source "$ROOT_DIR/lib/findings.sh"
  source "$ROOT_DIR/modules/firewall.sh"

  finding_reset

  local out_file="$tmp_dir/fw-zone.out"
  check_active_zone_rules >"$out_file"

  [[ ! -s "$out_file" ]] ||
    fail "check_active_zone_rules should store findings, not print"

  [[ "$(findings_count)" -eq 1 ]] ||
    fail "denied zone should emit one FW-003 finding"

  [[ "$(findings_get 0 id)" == "FW-003" ]] ||
    fail "denied zone finding should be FW-003"

  [[ "$(findings_get 0 severity)" == "info" ]] ||
    fail "denied zone should be info, not crash"

  [[ "$(findings_get 0 actual)" == *"public: unavailable"* ]] ||
    fail "FW-003 should aggregate the denied zone"

  out_file="$tmp_dir/fw-ports.out"
  check_broad_port_ranges >"$out_file"

  [[ ! -s "$out_file" ]] ||
    fail "check_broad_port_ranges should store findings, not print"

  [[ "$(findings_count)" -eq 2 ]] ||
    fail "audit should continue after a denied zone"
}

test_os_release_safe_parsing() {
  source "$ROOT_DIR/modules/host.sh"

  local os_fixture="$tmp_dir/os-release-fixture"

  # 1. Standard Fedora-like release data
  cat >"$os_fixture" <<'EOF'
NAME="Fedora Linux"
VERSION="42 (Rawhide)"
ID=fedora
VERSION_ID=42
PRETTY_NAME="Fedora Linux 42 (Rawhide)"
EOF
  OS_RELEASE_FILE="$os_fixture"
  [[ "$(get_os_name)" == "Fedora Linux" ]] || fail "Fedora-like NAME parsing failed"
  [[ "$(get_os_version)" == "42 (Rawhide)" ]] || fail "Fedora-like VERSION parsing failed"

  # 2. Quoted strings containing spaces and unquoted values
  cat >"$os_fixture" <<'EOF'
NAME='Enterprise Linux Server'
VERSION=9.4
EOF
  [[ "$(get_os_name)" == "Enterprise Linux Server" ]] || fail "Single-quoted NAME parsing failed"
  [[ "$(get_os_version)" == "9.4" ]] || fail "Unquoted VERSION parsing failed"

  # 3. Escaped quote and backslash behavior
  cat >"$os_fixture" <<'EOF'
NAME="Custom \"Secure\" OS"
VERSION="Version \\1.0\\"
EOF
  [[ "$(get_os_name)" == 'Custom "Secure" OS' ]] || fail "Escaped quote parsing failed"
  [[ "$(get_os_version)" == "Version \\1.0\\" ]] || fail "Escaped backslash parsing failed"

  # 3b. Consecutive backslashes and escaped quotes round-trip
  cat >"$os_fixture" <<'EOF'
NAME="Prefix \\\"Quoted\\\" Suffix"
VERSION="Version \\\\1.0\\\\"
EOF
  [[ "$(get_os_name)" == 'Prefix \"Quoted\" Suffix' ]] || fail "Escaped backslash and quote parsing failed"
  [[ "$(get_os_version)" == "Version \\\\1.0\\\\" ]] || fail "Consecutive backslashes parsing failed"

  cat >"$os_fixture" <<'EOF'
NAME="Quad\\\\Backslash"
VERSION="Version \\\\\\\\2.0"
EOF
  [[ "$(get_os_name)" == 'Quad\\Backslash' ]] || fail "Quad backslash parsing failed"
  [[ "$(get_os_version)" == "Version \\\\\\\\2.0" ]] || fail "Eight backslashes parsing failed"

  # 4. Missing fields
  cat >"$os_fixture" <<'EOF'
ID=minimal
SOME_OTHER_VAR="Value"
EOF
  [[ "$(get_os_name)" == "Unknown" ]] || fail "Missing NAME should return Unknown"
  [[ "$(get_os_version)" == "Unknown" ]] || fail "Missing VERSION should return Unknown"

  # 5. Malformed fields: unclosed quote
  cat >"$os_fixture" <<'EOF'
NAME="Unclosed quote string
VERSION=1.0
EOF
  [[ "$(get_os_name)" == "Unknown" ]] || fail "Unclosed quote in NAME must return Unknown"
  [[ "$(get_os_version)" == "1.0" ]] || fail "VERSION should parse despite malformed NAME"

  # 5b. Malformed fields: unclosed quote ending in escaped quote
  cat >"$os_fixture" <<'EOF'
NAME="Unclosed ending in escaped quote\"
VERSION="Valid 1.0"
EOF
  [[ "$(get_os_name)" == "Unknown" ]] || fail "Quote ending in escaped quote must return Unknown"
  [[ "$(get_os_version)" == "Valid 1.0" ]] || fail "VERSION should parse when preceding NAME has escaped quote"

  # 6. Malformed unquoted value containing spaces
  cat >"$os_fixture" <<'EOF'
NAME=Unquoted With Spaces
VERSION="1.0"
EOF
  [[ "$(get_os_name)" == "Unknown" ]] || fail "Unquoted string with spaces must return Unknown"

  # 7. Malicious command substitution payload: prove no side-effect execution
  local canary_file="$tmp_dir/os_release_exploit_canary.txt"
  rm -f "$canary_file"
  cat >"$os_fixture" <<EOF
NAME="\$(touch '$canary_file' && echo 'PwnedOS')"
VERSION="\$(touch '$canary_file' && echo '0.0.0')"
EOF
  local actual_name
  actual_name="$(get_os_name)"
  local actual_version
  actual_version="$(get_os_version)"

  [[ ! -e "$canary_file" ]] || fail "CRITICAL: Malicious os-release payload executed arbitrary command!"
  [[ "$actual_name" == *'touch'* ]] || fail "Command substitution must be treated as literal string"
  [[ "$actual_version" == *'touch'* ]] || fail "Command substitution must be treated as literal string"
}

test_json_escaping_rfc8259() {
  source "$ROOT_DIR/lib/findings.sh"
  source "$ROOT_DIR/reporters/json.sh"

  finding_reset

  # String containing: backslash, quotes, newline, CR, tab, backspace, form feed, ESC, bell, and UTF-8 characters
  local test_desc="Backslash: \\ Quotes: \" Newline: "$'\n'" CR: "$'\r'" Tab: "$'\t'
  local test_actual="BS: "$'\b'" FF: "$'\f'" ESC: "$'\e'" Bell: "$'\a'" Unicode: ñáéíóú 世界 🚀"

  finding \
    id=JSON-001 \
    category=test \
    severity=pass \
    title="JSON Escaping Test" \
    description="$test_desc" \
    expected="Valid RFC 8259 JSON" \
    actual="$test_actual" \
    recommendation="All control chars escaped"

  local json_report_file="$tmp_dir/rfc8259_report.json"
  write_json_report "$json_report_file"

  [[ -s "$json_report_file" ]] || fail "JSON report file should not be empty"

  # Validate using perl JSON::PP
  perl -MJSON::PP -e '
    my $file = $ARGV[0];
    open(my $fh, "<:raw", $file) or die "Cannot open $file: $!";
    my $content = do { local $/; <$fh> };
    close($fh);

    my $data = eval { JSON::PP->new->decode($content) };
    die "JSON::PP parse error: $@" if $@;
    die "Invalid root: not an object" unless ref($data) eq "HASH";
    die "Missing findings array" unless ref($data->{findings}) eq "ARRAY";

    my $f = $data->{findings}->[0];
    die "Incorrect ID" unless $f->{id} eq "JSON-001";
    die "Missing description" unless $f->{description} =~ /Backslash: \\ Quotes: \"/;
    die "Missing backspace in actual" unless $f->{actual} =~ /\x08/;
    die "Missing formfeed in actual" unless $f->{actual} =~ /\x0c/;
    die "Missing ESC in actual" unless $f->{actual} =~ /\x1b/;
    die "Missing Unicode in actual" unless $f->{actual} =~ /世界/;
  ' "$json_report_file" || fail "RFC 8259 JSON parsing failed via JSON::PP"

  finding_reset
}

test_symlink_aware_permissions() {
  source "$ROOT_DIR/lib/findings.sh"
  source "$ROOT_DIR/modules/permissions.sh"

  local perm_fixture_dir="$tmp_dir/perm_fixtures"
  mkdir -p "$perm_fixture_dir"

  # --- 1. /etc/shadow tests ---
  # Mock stat for unprivileged test environment to simulate root-owned shadow file
  cat >"$bin_dir/stat" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *"%a"*) printf '%s\n' '0' ;;
  *"%U"*) printf '%s\n' 'root' ;;
  *"%G"*) printf '%s\n' 'root' ;;
  *) /usr/bin/stat "$@" ;;
esac
EOF
  chmod +x "$bin_dir/stat"

  local real_shadow="$perm_fixture_dir/shadow_real"
  touch "$real_shadow"

  # Test valid regular shadow
  finding_reset
  check_shadow_permissions SHADOW-001 "$real_shadow"
  [[ "$(findings_get 0 id)" == "SHADOW-001" ]] || fail "Expected SHADOW-001"
  [[ "$(findings_get 0 severity)" == "pass" ]] || fail "Restricted root shadow should pass"

  # Test valid symlink pointing to shadow
  local sym_shadow="$perm_fixture_dir/shadow_symlink"
  ln -s "$real_shadow" "$sym_shadow"
  finding_reset
  check_shadow_permissions SHADOW-001 "$sym_shadow"
  [[ "$(findings_get 0 id)" == "SHADOW-001" ]] || fail "Expected SHADOW-001"
  [[ "$(findings_get 0 severity)" == "critical" ]] || fail "Shadow symlink must be critical"
  [[ "$(findings_get 0 title)" == *"symbolic link"* ]] || fail "Title must identify symbolic link"
  [[ "$(findings_get 0 actual)" == *"Symbolic link pointing to"* ]] || fail "Actual must indicate symlink target"

  # Test broken symlink
  local broken_shadow="$perm_fixture_dir/shadow_broken"
  ln -s "$perm_fixture_dir/nonexistent_shadow_target" "$broken_shadow"
  finding_reset
  check_shadow_permissions SHADOW-001 "$broken_shadow"
  [[ "$(findings_get 0 id)" == "SHADOW-001" ]] || fail "Expected SHADOW-001"
  [[ "$(findings_get 0 severity)" == "critical" ]] || fail "Broken shadow symlink must be critical"
  [[ "$(findings_get 0 title)" == *"symbolic link"* ]] || fail "Broken symlink must NOT report as not found"

  # Test missing shadow
  finding_reset
  check_shadow_permissions SHADOW-001 "$perm_fixture_dir/genuinely_missing_shadow"
  [[ "$(findings_get 0 id)" == "SHADOW-001" ]] || fail "Expected SHADOW-001"
  [[ "$(findings_get 0 severity)" == "info" ]] || fail "Missing shadow should be info"
  [[ "$(findings_get 0 title)" == *"not found"* ]] || fail "Missing shadow title must say not found"

  rm -f "$bin_dir/stat"

  # --- 2. .ssh directory tests ---
  local mock_home="$perm_fixture_dir/mock_home"
  mkdir -p "$mock_home"

  # Test .ssh as regular directory
  local mock_ssh="$mock_home/.ssh"
  mkdir -p "$mock_ssh"
  chmod 700 "$mock_ssh"
  finding_reset
  check_ssh_directory_permissions "$mock_home"
  [[ "$(findings_get 0 id)" == "PERM-006" ]] || fail "Expected PERM-006"

  # Test .ssh as symbolic link
  rm -rf "$mock_ssh"
  local real_ssh_target="$perm_fixture_dir/real_ssh_dir"
  mkdir -p "$real_ssh_target"
  ln -s "$real_ssh_target" "$mock_ssh"
  finding_reset
  check_ssh_directory_permissions "$mock_home"
  [[ "$(findings_get 0 id)" == "PERM-006" ]] || fail "Expected PERM-006"
  [[ "$(findings_get 0 severity)" == "high" ]] || fail ".ssh symlink must be high severity"
  [[ "$(findings_get 0 title)" == *".ssh is a symbolic link"* ]] || fail "Title must identify .ssh symlink"

  # Test .ssh as broken symbolic link
  rm -f "$mock_ssh"
  ln -s "$perm_fixture_dir/nonexistent_ssh_target" "$mock_ssh"
  finding_reset
  check_ssh_directory_permissions "$mock_home"
  [[ "$(findings_get 0 id)" == "PERM-006" ]] || fail "Expected PERM-006"
  [[ "$(findings_get 0 severity)" == "high" ]] || fail "Broken .ssh symlink must be high severity"
  [[ "$(findings_get 0 title)" == *".ssh is a symbolic link"* ]] || fail "Title must identify .ssh symlink"

  # Test .ssh missing
  rm -f "$mock_ssh"
  finding_reset
  check_ssh_directory_permissions "$mock_home"
  [[ "$(findings_get 0 id)" == "PERM-006" ]] || fail "Expected PERM-006"
  [[ "$(findings_get 0 severity)" == "info" ]] || fail "Missing .ssh must be info"
  [[ "$(findings_get 0 title)" == *".ssh directory not found"* ]] || fail "Title must say not found"

  # --- 3. authorized_keys tests ---
  mkdir -p "$mock_ssh"
  chmod 700 "$mock_ssh"
  local auth_keys="$mock_ssh/authorized_keys"

  # Test authorized_keys as valid regular file
  touch "$auth_keys"
  chmod 600 "$auth_keys"
  finding_reset
  check_authorized_keys_permissions "$mock_home"
  [[ "$(findings_get 0 id)" == "PERM-007" ]] || fail "Expected PERM-007"

  # Test authorized_keys as symbolic link
  rm -f "$auth_keys"
  local real_keys_target="$perm_fixture_dir/real_keys_target"
  touch "$real_keys_target"
  ln -s "$real_keys_target" "$auth_keys"
  finding_reset
  check_authorized_keys_permissions "$mock_home"
  [[ "$(findings_get 0 id)" == "PERM-007" ]] || fail "Expected PERM-007"
  [[ "$(findings_get 0 severity)" == "high" ]] || fail "authorized_keys symlink must be high severity"
  [[ "$(findings_get 0 title)" == *"authorized_keys is a symbolic link"* ]] || fail "Title must identify symlink"

  # Test authorized_keys as broken symbolic link
  rm -f "$auth_keys"
  ln -s "$perm_fixture_dir/nonexistent_keys_target" "$auth_keys"
  finding_reset
  check_authorized_keys_permissions "$mock_home"
  [[ "$(findings_get 0 id)" == "PERM-007" ]] || fail "Expected PERM-007"
  [[ "$(findings_get 0 severity)" == "high" ]] || fail "Broken authorized_keys symlink must be high severity"
  [[ "$(findings_get 0 title)" == *"authorized_keys is a symbolic link"* ]] || fail "Title must identify symlink"

  # Test authorized_keys missing
  rm -f "$auth_keys"
  finding_reset
  check_authorized_keys_permissions "$mock_home"
  [[ "$(findings_get 0 id)" == "PERM-007" ]] || fail "Expected PERM-007"
  [[ "$(findings_get 0 severity)" == "info" ]] || fail "Missing authorized_keys must be info"
  [[ "$(findings_get 0 title)" == *"authorized_keys not found"* ]] || fail "Title must say not found"

  # --- 4. Unexpected file type in check_file_permissions ---
  local fifo_file="$perm_fixture_dir/test_fifo"
  mkfifo "$fifo_file"
  finding_reset
  check_file_permissions TEST-FIFO "$fifo_file" 644 "$(id -un)" "$(id -gn)"
  [[ "$(findings_get 0 id)" == "TEST-FIFO" ]] || fail "Expected TEST-FIFO"
  [[ "$(findings_get 0 severity)" == "high" ]] || fail "Special file must be high severity"
  [[ "$(findings_get 0 title)" == *"unexpected file type"* ]] || fail "Title must identify unexpected file type"
  rm -f "$fifo_file"

  finding_reset
}

test_bounded_dnf_execution() {
  source "$ROOT_DIR/lib/findings.sh"
  source "$ROOT_DIR/modules/updates.sh"

  # 1. Fail closed when timeout executable is unavailable: DNF must NOT be executed
  local no_timeout_bin="$tmp_dir/no_timeout_bin"
  mkdir -p "$no_timeout_bin"
  ln -s "$(command -v bash)" "$no_timeout_bin/bash"
  ln -s "$(command -v awk)" "$no_timeout_bin/awk"

  local no_timeout_canary="$tmp_dir/dnf_ran_when_no_timeout.canary"
  rm -f "$no_timeout_canary"
  cat >"$no_timeout_bin/dnf" <<EOF
#!/usr/bin/env bash
touch '$no_timeout_canary'
exit 0
EOF
  chmod +x "$no_timeout_bin/dnf"

  (
    export PATH="$no_timeout_bin"
    finding_reset
    check_pending_updates
    [[ ! -e "$no_timeout_canary" ]] || fail "DNF was executed when timeout was unavailable (check_pending_updates)"
    [[ "$(findings_count)" -eq 1 ]] || fail "Missing timeout should emit one finding (check_pending_updates)"
    [[ "$(findings_get 0 id)" == "UPDATE-001" ]] || fail "Expected UPDATE-001 for missing timeout"
    [[ "$(findings_get 0 severity)" == "info" ]] || fail "Expected info severity for missing timeout"
    [[ "$(findings_get 0 title)" == *"wrapper unavailable"* ]] || fail "Title must identify wrapper unavailable"
    [[ "$(findings_get 0 actual)" == *"timeout command unavailable"* ]] || fail "Actual must identify timeout command unavailable"

    finding_reset
    check_security_updates
    [[ ! -e "$no_timeout_canary" ]] || fail "DNF was executed when timeout was unavailable (check_security_updates)"
    [[ "$(findings_count)" -eq 1 ]] || fail "Missing timeout should emit one finding (check_security_updates)"
    [[ "$(findings_get 0 id)" == "UPDATE-002" ]] || fail "Expected UPDATE-002 for missing timeout"
    [[ "$(findings_get 0 severity)" == "info" ]] || fail "Expected info severity for missing timeout"
    [[ "$(findings_get 0 title)" == *"wrapper unavailable"* ]] || fail "Title must identify wrapper unavailable"
    [[ "$(findings_get 0 actual)" == *"timeout command unavailable"* ]] || fail "Actual must identify timeout command unavailable"
  )

  # 2. Invalid LSA_DNF_TIMEOUT: DNF must NOT be executed
  local invalid_timeout_canary="$tmp_dir/dnf_ran_when_invalid_timeout.canary"
  rm -f "$invalid_timeout_canary"
  cat >"$bin_dir/dnf" <<EOF
#!/usr/bin/env bash
touch '$invalid_timeout_canary'
exit 0
EOF
  chmod +x "$bin_dir/dnf"

  local invalid_vals=("0" "-5" "abc" "9999" "05" "301")
  for invalid_val in "${invalid_vals[@]}"; do
    rm -f "$invalid_timeout_canary"

    finding_reset
    LSA_DNF_TIMEOUT="$invalid_val" check_pending_updates
    [[ ! -e "$invalid_timeout_canary" ]] || fail "DNF executed with invalid timeout '$invalid_val' (check_pending_updates)"
    [[ "$(findings_count)" -eq 1 ]] || fail "Invalid timeout must emit one finding"
    [[ "$(findings_get 0 id)" == "UPDATE-001" ]] || fail "Expected UPDATE-001 for invalid timeout"
    [[ "$(findings_get 0 severity)" == "info" ]] || fail "Invalid timeout severity must be info"
    [[ "$(findings_get 0 title)" == *"timeout configuration invalid"* ]] || fail "Title must indicate invalid configuration"
    [[ "$(findings_get 0 actual)" == *"Invalid timeout value: $invalid_val"* ]] || fail "Actual must report invalid timeout"

    rm -f "$invalid_timeout_canary"

    finding_reset
    LSA_DNF_TIMEOUT="$invalid_val" check_security_updates
    [[ ! -e "$invalid_timeout_canary" ]] || fail "DNF executed with invalid timeout '$invalid_val' (check_security_updates)"
    [[ "$(findings_count)" -eq 1 ]] || fail "Invalid timeout must emit one finding"
    [[ "$(findings_get 0 id)" == "UPDATE-002" ]] || fail "Expected UPDATE-002 for invalid timeout"
    [[ "$(findings_get 0 severity)" == "info" ]] || fail "Invalid timeout severity must be info"
    [[ "$(findings_get 0 title)" == *"timeout configuration invalid"* ]] || fail "Title must indicate invalid configuration"
    [[ "$(findings_get 0 actual)" == *"Invalid timeout value: $invalid_val"* ]] || fail "Actual must report invalid timeout"
  done

  # 3. Timeout simulation on check-update (exit code 124)
  cat >"$bin_dir/dnf" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "check-update" ]]; then
  sleep 5
  exit 0
fi
exit 0
EOF
  chmod +x "$bin_dir/dnf"

  finding_reset
  LSA_DNF_TIMEOUT=1 check_pending_updates

  [[ "$(findings_count)" -eq 1 ]] || fail "Timeout check-update should emit one finding"
  [[ "$(findings_get 0 id)" == "UPDATE-001" ]] || fail "Finding ID must be UPDATE-001"
  [[ "$(findings_get 0 severity)" == "info" ]] || fail "Timeout severity must be info"
  [[ "$(findings_get 0 title)" == *"timed out"* ]] || fail "Title must indicate timeout"
  [[ "$(findings_get 0 actual)" == *"timed out"* ]] || fail "Actual must indicate timeout"

  # 4. Timeout simulation on updateinfo (exit code 124)
  cat >"$bin_dir/dnf" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "updateinfo" ]]; then
  sleep 5
  exit 0
fi
exit 0
EOF
  chmod +x "$bin_dir/dnf"

  finding_reset
  LSA_DNF_TIMEOUT=1 check_security_updates

  [[ "$(findings_count)" -eq 1 ]] || fail "Timeout updateinfo should emit one finding"
  [[ "$(findings_get 0 id)" == "UPDATE-002" ]] || fail "Finding ID must be UPDATE-002"
  [[ "$(findings_get 0 severity)" == "info" ]] || fail "Timeout severity must be info"
  [[ "$(findings_get 0 title)" == *"timed out"* ]] || fail "Title must indicate timeout"
  [[ "$(findings_get 0 actual)" == *"timed out"* ]] || fail "Actual must indicate timeout"

  # 5. dnf check-update exit code 100 correctly classified as Pending package updates detected
  cat >"$bin_dir/dnf" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "check-update" ]]; then
  echo "kernel.x86_64 6.12.0-1.el9 updates"
  exit 100
fi
exit 0
EOF
  chmod +x "$bin_dir/dnf"

  finding_reset
  LSA_DNF_TIMEOUT=15 check_pending_updates
  [[ "$(findings_count)" -eq 1 ]] || fail "Exit code 100 should emit one finding"
  [[ "$(findings_get 0 id)" == "UPDATE-001" ]] || fail "Expected UPDATE-001"
  [[ "$(findings_get 0 severity)" == "info" ]] || fail "Severity for updates available must be info"
  [[ "$(findings_get 0 title)" == "Pending package updates detected" ]] || fail "Title should report pending updates"

  # 6. Verify non-interactive arguments and stdin redirection with clean exit 0
  cat >"$bin_dir/dnf" <<'EOF'
#!/usr/bin/env bash
# Verify stdin is not an interactive terminal
if [ -t 0 ]; then
  echo "Interactive terminal stdin detected" >&2
  exit 2
fi

case "$*" in
  *"--assumeno"*) ;;
  *)
    echo "Missing --assumeno argument" >&2
    exit 2
    ;;
esac
exit 0
EOF
  chmod +x "$bin_dir/dnf"

  finding_reset
  check_pending_updates
  [[ "$(findings_get 0 id)" == "UPDATE-001" ]] || fail "Expected UPDATE-001"
  [[ "$(findings_get 0 severity)" == "pass" ]] || fail "Expected pass on non-interactive clean dnf"

  finding_reset
}

test_dnf_updates_available
test_dnf_failure
test_journal_permission_denied
test_sshlog_journal_failure
test_missing_target_user
test_missing_sudoers
test_missing_os_release
test_firewall_zone_failure
test_os_release_safe_parsing
test_json_escaping_rfc8259
test_symlink_aware_permissions
test_bounded_dnf_execution

printf '%s\n' 'runtime hardening tests passed'
