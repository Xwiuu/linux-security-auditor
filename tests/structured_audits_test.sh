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

cat >"$bin_dir/dnf" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *"check-update"*) exit 0 ;;
  *"updateinfo"*) exit 0 ;;
esac
EOF

cat >"$bin_dir/ps" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *user,pid,comm,args*) printf '%s\n' 'root 100 sshd /usr/sbin/sshd' ;;
  *user=,pid=*) printf '%s\n' 'root 100' ;;
esac
EOF

cat >"$bin_dir/readlink" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '/usr/bin/env'
EOF

cat >"$bin_dir/stat" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *%a*) printf '%s\n' '755' ;;
  *%U*) printf '%s\n' 'root' ;;
esac
EOF

cat >"$bin_dir/ss" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port'
EOF

cat >"$bin_dir/firewall-cmd" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *"--state"*) printf '%s\n' 'running' ;;
  *"--get-active-zones"*) printf '%s\n' 'public' '  interfaces: eth0' ;;
  *"--list-all"*) printf '%s\n' 'public (active)' ;;
  *"--list-ports"*) printf '%s\n' '22/tcp' ;;
esac
EOF

chmod +x "$bin_dir"/*
export PATH="$bin_dir:$PATH"

source "$ROOT_DIR/lib/findings.sh"
source "$ROOT_DIR/modules/updates.sh"
source "$ROOT_DIR/modules/processes.sh"
source "$ROOT_DIR/modules/ports.sh"
source "$ROOT_DIR/modules/firewall.sh"

finding_reset
reset_firewall_state

check_pending_updates
check_security_updates
summarize_root_processes
check_root_process_executables
check_root_process_executable_locations
summarize_listening_ports
list_exposed_tcp_ports
check_firewalld_status
check_active_zones
check_active_zone_rules
check_broad_port_ranges

expected_ids=(
  UPDATE-001 UPDATE-002
  PROC-001 PROC-002 PROC-003
  PORT-001 PORT-002 PORT-003 PORT-004 PORT-005 PORT-006 PORT-007
  FW-001 FW-002 FW-003 FW-004
)

[[ "$(findings_count)" -eq 16 ]] ||
  fail "expected 16 structured findings"

for i in "${!expected_ids[@]}"; do
  actual_id="$(findings_get "$i" id)"

  [[ "$actual_id" == "${expected_ids[$i]}" ]] ||
    fail "unexpected finding id at index $i: $actual_id"
done

printf '%s\n' 'structured audit tests passed'
