#!/usr/bin/env bash

get_uid_zero_users() {
    awk -F: '$3 == 0 { print $1 }' /etc/passwd
}

audit_uid_zero_users() {
  local users
  users="$(get_uid_zero_users)"

  if [[ "$users" == "root" ]]; then
    printf '%s\n' '[PASS] USER-001 Only root has UID 0'
  else
    printf '%s\n' '[HIGH] USER-001 Multiple users with UID 0 detected'
    printf '%s\n' "$users"
  fi
}

get_interactive_users() {
  awk -F: '$7 !~ /(nologin|false)$/ { print $1 ":" $7 }' /etc/passwd
}

audit_interactive_users() {
    printf '%s\n' '[INFO] USER-002 Interactive shell users:'
    get_interactive_users
}


get_admin_users() {
  if getent group wheel >/dev/null 2>&1; then
    getent group wheel | awk -F: '{ print $4 }'
  elif getent group sudo >/dev/null 2>&1; then
    getent group sudo | awk -F: '{ print $4 }'
  else
    printf '%s\n' 'none'
  fi
}


audit_admin_users() {
  printf '%s\n' '[INFO] USER-003 Administrative group users:'
  get_admin_users
}


get_empty_password_users() {
  if [[ ! -r /etc/shadow ]]; then
    return 2
  fi

  awk -F: '$2 == "" { print $1 }' /etc/shadow
}

audit_empty_password_users() {
  local users
  local status

  users="$(get_empty_password_users)" || status=$?

  if [[ "${status:-0}" -eq 2 ]]; then
    printf '%s\n' '[INFO] USER-004 Password audit requires root privileges'
    return 0
  fi

  if [[ -z "$users" ]]; then
    printf '%s\n' '[PASS] USER-004 No accounts with empty passwords'
  else
    printf '%s\n' '[CRITICAL] USER-004 Accounts with empty passwords detected'
    printf '%s\n' "$users"
  fi
}

get_locked_users() {
  if [[ ! -r /etc/shadow ]]; then
    return 2
  fi

  awk -F: '$2 ~ /^(!|\*)/ { print $1 }' /etc/shadow
}

audit_locked_users() {
  local users
  local status=0

  users="$(get_locked_users)" || status=$?

  if [[ "$status" -eq 2 ]]; then
    printf '%s\n' '[INFO] USER-005 Locked account audit requires root privileges'
    return 0
  fi

  printf '%s\n' '[INFO] USER-005 Locked accounts:'

  if [[ -z "$users" ]]; then
    printf '%s\n' 'none'
  else
    printf '%s\n' "$users"
  fi
}
