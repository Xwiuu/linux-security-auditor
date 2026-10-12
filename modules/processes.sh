#!/usr/bin/env bash

list_root_processes() {
  ps -eo user,pid,comm,args --no-headers |
    awk '
      $1 == "root" &&
      $4 !~ /^\[/ &&
      $3 != "sudo" &&
      $3 != "bash" &&
      $3 != "ps" &&
      $3 != "awk"
    '
}

summarize_root_processes() {
  local count

  count="$(list_root_processes | wc -l)"

  printf '[INFO] PROC-001 Root userspace processes: %s\n' "$count"
}

check_root_process_executables() {
  local pid
  local exe
  local mode
  local owner
  local group_digit
  local other_digit
  local suspicious=0

  while read -r pid; do
    exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"

    [[ -z "$exe" ]] && continue
    [[ ! -e "$exe" ]] && continue

    mode="$(stat -c '%a' "$exe" 2>/dev/null || true)"
    owner="$(stat -c '%U' "$exe" 2>/dev/null || true)"

    [[ -z "$mode" ]] && continue

    group_digit="${mode: -2:1}"
    other_digit="${mode: -1}"

    if [[ "$owner" != "root" ]]; then
      printf '[HIGH] PROC-002 Root process executable not owned by root: PID=%s PATH=%s OWNER=%s\n' \
        "$pid" "$exe" "$owner"
      suspicious=1

    elif (((group_digit & 2) != 0 || (other_digit & 2) != 0)); then
      printf '[HIGH] PROC-002 Root process executable writable by group/others: PID=%s PATH=%s MODE=%s\n' \
        "$pid" "$exe" "$mode"
      suspicious=1
    fi
  done < <(
    ps -eo user=,pid= |
      awk '$1 == "root" { print $2 }'
  )

  if [[ "$suspicious" -eq 0 ]]; then
    printf '%s\n' '[PASS] PROC-002 No unsafe root process executables detected'
  fi
}

check_root_process_executable_locations() {
  local pid
  local exe
  local suspicious=0

  while read -r pid; do
    exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"

    [[ -z "$exe" ]] && continue
    [[ ! -e "$exe" ]] && continue

    case "$exe" in
      /tmp/* | /var/tmp/* | /home/* | /run/user/*)
        printf '[HIGH] PROC-003 Root process executable in unusual location: PID=%s PATH=%s\n' "$pid" "$exe"
        suspicious=1
        ;;
    esac
  done < <(
    ps -eo user=,pid= |
      awk '$1 == "root" { print $2 }'
  )

  if [[ "$suspicious" -eq 0 ]]; then
    printf '%s\n' '[PASS] PROC-003 No root processes running from unusual locations'
  fi
}
