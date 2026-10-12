#!/usr/bin/env bash

get_uid_zero_users() {
    awk -F: '$3 == 0 { print $1 }' /etc/passwd
}

audit_uid_zero_users() {
  local users
  users="$(get_uid_zero_users)"

  if [[ "$users" == "root" ]]; then
    finding \
      id=USER-001 \
      category=users \
      severity=pass \
      title="Only root has UID 0" \
      description="No additional accounts with UID 0 were detected" \
      expected="Only root should have UID 0" \
      actual="root" \
      recommendation="No action required"
  else
    finding \
      id=USER-001 \
      category=users \
      severity=high \
      title="Multiple users with UID 0 detected" \
      description="Accounts other than root have UID 0 and therefore root-equivalent privileges" \
      expected="Only root should have UID 0" \
      actual="$users" \
      recommendation="Review and remove unnecessary UID 0 assignments"
  fi
}

get_interactive_users() {
  awk -F: '$7 !~ /(nologin|false)$/ { print $1 ":" $7 }' /etc/passwd
}

audit_interactive_users() {
  local users

  users="$(get_interactive_users)"

  if [[ -z "$users" ]]; then
    users="none"
  fi

  finding \
    id=USER-002 \
    category=users \
    severity=info \
    title="Interactive shell users" \
    description="Accounts that can log in because they have a non-nologin shell" \
    expected="Only required accounts have a login shell" \
    actual="$users" \
    recommendation="Confirm every interactive account is still required"
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
  local users

  users="$(get_admin_users)"

  if [[ -z "$users" ]]; then
    users="none"
  fi

  finding \
    id=USER-003 \
    category=users \
    severity=info \
    title="Administrative group users" \
    description="Accounts holding administrative privileges through the wheel or sudo group" \
    expected="Administrative access limited to a known set of accounts" \
    actual="$users" \
    recommendation="Confirm every administrative account is still required"
}


get_empty_password_users() {
  if [[ ! -r /etc/shadow ]]; then
    return 2
  fi

  awk -F: '$2 == "" { print $1 }' /etc/shadow
}

audit_empty_password_users() {
  local users
  local status=0

  users="$(get_empty_password_users)" || status=$?

  if [[ "$status" -eq 2 ]]; then
    finding \
      id=USER-004 \
      category=users \
      severity=info \
      title="Password audit requires root privileges" \
      description="/etc/shadow could not be read, so empty passwords were not evaluated" \
      expected="/etc/shadow readable for the audit" \
      actual="unreadable" \
      recommendation="Run the audit as root to evaluate password hashes"
    return 0
  fi

  if [[ -z "$users" ]]; then
    finding \
      id=USER-004 \
      category=users \
      severity=pass \
      title="No accounts with empty passwords" \
      description="No account in /etc/shadow has an empty password hash" \
      expected="No empty password hashes" \
      actual="none" \
      recommendation="No action required"
  else
    finding \
      id=USER-004 \
      category=users \
      severity=critical \
      title="Accounts with empty passwords detected" \
      description="Accounts with an empty password hash can authenticate without a password" \
      expected="No empty password hashes" \
      actual="$users" \
      recommendation="Lock or re-hash the affected accounts immediately"
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
    finding \
      id=USER-005 \
      category=users \
      severity=info \
      title="Locked account audit requires root privileges" \
      description="/etc/shadow could not be read, so locked accounts were not evaluated" \
      expected="/etc/shadow readable for the audit" \
      actual="unreadable" \
      recommendation="Run the audit as root to evaluate locked accounts"
    return 0
  fi

  if [[ -z "$users" ]]; then
    users="none"
  fi

  finding \
    id=USER-005 \
    category=users \
    severity=info \
    title="Locked accounts" \
    description="Accounts with a locked password hash, listed for review" \
    expected="Locked accounts reviewed" \
    actual="$users" \
    recommendation="Confirm no required account is locked out"
}
