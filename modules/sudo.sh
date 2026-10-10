#!/usr/bin/env bash

check_sudoers_syntax() {
  if ! command -v visudo >/dev/null 2>&1; then
    printf '%s\n' '[INFO] SUDO-001 visudo not available'
    return 0
  fi

  if visudo -c >/dev/null 2>&1; then
    printf '%s\n' '[PASS] SUDO-001 sudoers syntax is valid'
  else
    printf '%s\n' '[HIGH] SUDO-001 sudoers syntax errors detected'
  fi
}

check_sudoers_permissions() {
  local mode
  local owner
  local group

  mode="$(stat -c '%a' /etc/sudoers)"
  owner="$(stat -c '%U' /etc/sudoers)"
  group="$(stat -c '%G' /etc/sudoers)"

  if [[ "$mode" == "440" && "$owner" == "root" && "$group" == "root" ]]; then
    printf '%s\n' '[PASS] SUDO-002 /etc/sudoers permissions are correct'
  else
    printf '%s\n' '[HIGH] SUDO-002 /etc/sudoers permissions differ from expected'
    printf '  Mode: %s\n' "$mode"
    printf '  Owner: %s\n' "$owner"
    printf '  Group: %s\n' "$group"
  fi
}

check_sudoers_d_permissions() {
  local file
  local found=0

  if [[ ! -d /etc/sudoers.d ]]; then
    printf '%s\n' '[INFO] SUDO-003 /etc/sudoers.d not found'
    return 0
  fi

  while IFS= read -r file; do
    found=1

    local mode
    local owner
    local group

    mode="$(stat -c '%a' "$file")"
    owner="$(stat -c '%U' "$file")"
    group="$(stat -c '%G' "$file")"

    if [[ "$mode" != "440" || "$owner" != "root" || "$group" != "root" ]]; then
      printf '%s\n' '[HIGH] SUDO-003 Invalid sudoers.d file permissions'
      printf '  File: %s\n' "$file"
      printf '  Mode: %s\n' "$mode"
      printf '  Owner: %s\n' "$owner"
      printf '  Group: %s\n' "$group"
    fi
  done < <(find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)

  if [[ "$found" -eq 0 ]]; then
    printf '%s\n' '[INFO] SUDO-003 No sudoers.d files found'
  fi
}

check_nopasswd_rules() {
  local matches

  matches="$(
    grep -RIn --include='*' 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null \
      | grep -Ev '^[^:]+:[0-9]+:[[:space:]]*#' \
      || true
  )"

  if [[ -z "$matches" ]]; then
    printf '%s\n' '[PASS] SUDO-004 No active NOPASSWD rules detected'
  else
    printf '%s\n' '[WARN] SUDO-004 Active NOPASSWD rules detected'
    printf '%s\n' "$matches"
  fi
}

check_broad_sudo_rules() {
  local matches

  matches="$(
    grep -RIn --include='*' -E 'ALL[[:space:]]*=[[:space:]]*\(ALL(:ALL)?\)[[:space:]]*ALL' \
      /etc/sudoers /etc/sudoers.d 2>/dev/null \
      | grep -Ev '^[^:]+:[0-9]+:[[:space:]]*#' \
      || true
  )"

  if [[ -z "$matches" ]]; then
    printf '%s\n' '[PASS] SUDO-005 No broad sudo rules detected'
  else
    printf '%s\n' '[INFO] SUDO-005 Broad sudo rules detected'
    printf '%s\n' "$matches"
  fi
}
