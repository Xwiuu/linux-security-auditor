#!/usr/bin/env bash

check_sshd_available() {
  if command -v sshd >/dev/null 2>&1; then
    printf '%s\n' '[PASS] SSH-001 sshd is available'
  else
    printf '%s\n' '[INFO] SSH-001 sshd is not installed'
  fi
}


get_sshd_option() {
  local option="$1"

  sshd -T 2>/dev/null | awk -v key="$option" '$1 == key { print $2; exit }'
}


check_root_login() {
  local value

  if ! value="$(get_sshd_option permitrootlogin)"; then
    printf '%s\n' '[INFO] SSH-002 Effective SSH configuration unavailable'
    return 0
  fi

  if [[ -z "$value" ]]; then
    printf '%s\n' '[INFO] SSH-002 Could not determine PermitRootLogin'
  elif [[ "$value" == "no" ]]; then
    printf '%s\n' '[PASS] SSH-002 Root login is disabled'
  else
    printf '[WARN] SSH-002 Root login setting: %s\n' "$value"
  fi
}


check_password_authentication() {
  local value

  if ! value="$(get_sshd_option passwordauthentication)"; then
    printf '%s\n' '[INFO] SSH-003 Effective SSH configuration unavailable'
    return 0
  fi

  if [[ -z "$value" ]]; then
    printf '%s\n' '[INFO] SSH-003 Could not determine PasswordAuthentication'
  elif [[ "$value" == "no" ]]; then
    printf '%s\n' '[PASS] SSH-003 Password authentication is disabled'
  else
    printf '[WARN] SSH-003 Password authentication setting: %s\n' "$value"
  fi
}


check_empty_passwords() {
  local value

  if ! value="$(get_sshd_option permitemptypasswords)"; then
    printf '%s\n' '[INFO] SSH-004 Effective SSH configuration unavailable'
    return 0
  fi

  if [[ -z "$value" ]]; then
    printf '%s\n' '[INFO] SSH-004 Could not determine PermitEmptyPasswords'
  elif [[ "$value" == "no" ]]; then
    printf '%s\n' '[PASS] SSH-004 Empty passwords are disabled'
  else
    printf '[HIGH] SSH-004 PermitEmptyPasswords setting: %s\n' "$value"
  fi
}

check_pubkey_authentication() {
  local value

  if ! value="$(get_sshd_option pubkeyauthentication)"; then
    printf '%s\n' '[INFO] SSH-005 Effective SSH configuration unavailable'
    return 0
  fi

  if [[ -z "$value" ]]; then
    printf '%s\n' '[INFO] SSH-005 Could not determine PubkeyAuthentication'
  elif [[ "$value" == "yes" ]]; then
    printf '%s\n' '[PASS] SSH-005 Public key authentication is enabled'
  else
    printf '[WARN] SSH-005 PubkeyAuthentication setting: %s\n' "$value"
  fi
}


check_max_auth_tries() {
  local value

  if ! value="$(get_sshd_option maxauthtries)"; then
    printf '%s\n' '[INFO] SSH-006 Effective SSH configuration unavailable'
    return 0
  fi

  if [[ -z "$value" ]]; then
    printf '%s\n' '[INFO] SSH-006 Could not determine MaxAuthTries'
  elif (( value <= 4 )); then
    printf '[PASS] SSH-006 MaxAuthTries is %s\n' "$value"
  else
    printf '[WARN] SSH-006 MaxAuthTries is %s\n' "$value"
  fi
}


check_x11_forwarding() {
  local value

  if ! value="$(get_sshd_option x11forwarding)"; then
    printf '%s\n' '[INFO] SSH-007 Effective SSH configuration unavailable'
    return 0
  fi

  if [[ -z "$value" ]]; then
    printf '%s\n' '[INFO] SSH-007 Could not determine X11Forwarding'
  elif [[ "$value" == "no" ]]; then
    printf '%s\n' '[PASS] SSH-007 X11 forwarding is disabled'
  else
    printf '[INFO] SSH-007 X11Forwarding setting: %s\n' "$value"
  fi
}
