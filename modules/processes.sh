#!/usr/bin/env bash

summarize_root_processes() {
  local output
  local status=0
  local count

  output="$(ps -eo user,pid,comm,args --no-headers 2>/dev/null)" || status=$?

  if ((status != 0)); then
    finding \
      id=PROC-001 \
      category=processes \
      severity=info \
      title="Root userspace processes could not be counted" \
      description="The process listing could not be read to count root userspace processes" \
      expected="Process listing available for auditing" \
      actual="ps exited with status $status" \
      recommendation="Verify ps availability and process visibility"

    return 0
  fi

  count="$(
    awk '
      $1 == "root" &&
      $4 !~ /^\[/ &&
      $3 != "sudo" &&
      $3 != "bash" &&
      $3 != "ps" &&
      $3 != "awk" {
        count++
      }
      END {
        print count + 0
      }
    ' <<<"$output"
  )"

  if ((count == 0)); then
    finding \
      id=PROC-001 \
      category=processes \
      severity=pass \
      title="No root userspace processes detected" \
      description="No root-owned userspace processes were found in the current process listing" \
      expected="Root userspace processes reviewed" \
      actual="0 root userspace processes" \
      recommendation="No action required"
  else
    finding \
      id=PROC-001 \
      category=processes \
      severity=info \
      title="Root userspace processes detected" \
      description="Root-owned userspace processes are running, which is common and not inherently risky" \
      expected="Root userspace processes reviewed" \
      actual="$count root userspace processes" \
      recommendation="Review the listed processes if unexpected for this host"
  fi
}

check_root_process_executables() {
  local output
  local status=0
  local pid
  local exe
  local mode
  local owner
  local group_digit
  local other_digit
  local issues=""

  output="$(ps -eo user=,pid= 2>/dev/null)" || status=$?

  if ((status != 0)); then
    finding \
      id=PROC-002 \
      category=processes \
      severity=info \
      title="Root process executables could not be audited" \
      description="The process listing could not be read to inspect root process executables" \
      expected="Process listing available for auditing" \
      actual="ps exited with status $status" \
      recommendation="Verify ps availability and process visibility"

    return 0
  fi

  while read -r pid; do
    [[ -z "$pid" ]] && continue

    exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"

    [[ -z "$exe" ]] && continue
    [[ ! -e "$exe" ]] && continue

    mode="$(stat -c '%a' "$exe" 2>/dev/null || true)"
    owner="$(stat -c '%U' "$exe" 2>/dev/null || true)"

    [[ -z "$mode" ]] && continue

    group_digit="${mode: -2:1}"
    other_digit="${mode: -1}"

    if [[ "$owner" != "root" ]]; then
      issues+="PID=$pid PATH=$exe OWNER=$owner; "

    elif (((group_digit & 2) != 0 || (other_digit & 2) != 0)); then
      issues+="PID=$pid PATH=$exe MODE=$mode writable by group/others; "
    fi
  done < <(awk '$1 == "root" { print $2 }' <<<"$output")

  if [[ -z "$issues" ]]; then
    finding \
      id=PROC-002 \
      category=processes \
      severity=pass \
      title="Root process executables are securely owned" \
      description="No unsafe ownership or permission conditions were detected for inspected root process executables" \
      expected="Secure ownership and permissions" \
      actual="No unsafe executables detected" \
      recommendation="No action required"
  else
    finding \
      id=PROC-002 \
      category=processes \
      severity=high \
      title="Unsafe root process executables detected" \
      description="One or more root-owned processes are executing files with unsafe ownership or permissions" \
      expected="Root process executables should be owned securely and not writable by unprivileged users" \
      actual="$issues" \
      recommendation="Review the listed executables and correct unsafe ownership or permissions"
  fi
}

check_root_process_executable_locations() {
  local output
  local status=0
  local pid
  local exe
  local issues=""

  output="$(ps -eo user=,pid= 2>/dev/null)" || status=$?

  if ((status != 0)); then
    finding \
      id=PROC-003 \
      category=processes \
      severity=info \
      title="Root process executable locations could not be audited" \
      description="The process listing could not be read to inspect root process executable locations" \
      expected="Process listing available for auditing" \
      actual="ps exited with status $status" \
      recommendation="Verify ps availability and process visibility"

    return 0
  fi

  while read -r pid; do
    [[ -z "$pid" ]] && continue

    exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"

    [[ -z "$exe" ]] && continue
    [[ ! -e "$exe" ]] && continue

    case "$exe" in
      /tmp/* | /var/tmp/* | /home/* | /run/user/*)
        issues+="PID=$pid PATH=$exe; "
        ;;
    esac
  done < <(awk '$1 == "root" { print $2 }' <<<"$output")

  if [[ -z "$issues" ]]; then
    finding \
      id=PROC-003 \
      category=processes \
      severity=pass \
      title="No root processes from unusual locations" \
      description="No root process executables were found in temporary or user-writable locations" \
      expected="Root process executables in standard system locations" \
      actual="No unusual locations detected" \
      recommendation="No action required"
  else
    finding \
      id=PROC-003 \
      category=processes \
      severity=medium \
      title="Root processes from unusual locations" \
      description="Root-owned processes are executing files from temporary or user-writable locations" \
      expected="Root process executables in standard system locations" \
      actual="$issues" \
      recommendation="Review the listed processes and confirm the binaries are legitimate"
  fi
}
