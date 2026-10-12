#!/usr/bin/env bash

SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers}"

check_sudoers_syntax() {
  local output
  local status=0

  if ! command -v visudo >/dev/null 2>&1; then
    finding \
      id=SUDO-001 \
      category=sudo \
      severity=info \
      title="sudoers syntax could not be audited" \
      description="visudo is not available" \
      expected="sudoers syntax validation available" \
      actual="visudo not found" \
      recommendation="Install or make visudo available"

    return 0
  fi

  output="$(visudo -c 2>&1)" || status=$?

  if ((status == 0)); then
    finding \
      id=SUDO-001 \
      category=sudo \
      severity=pass \
      title="sudoers syntax is valid" \
      description="The sudoers configuration passed syntax validation" \
      expected="Valid sudoers syntax" \
      actual="Syntax validation passed" \
      recommendation="No action required"

  elif grep -qiE 'permission denied|permissão negada' <<<"$output"; then
    finding \
      id=SUDO-001 \
      category=sudo \
      severity=info \
      title="sudoers syntax could not be audited" \
      description="The current process does not have sufficient permission to validate sudoers" \
      expected="Sufficient privilege to validate sudoers" \
      actual="Permission denied" \
      recommendation="Run the audit with sufficient privileges"

  else
    finding \
      id=SUDO-001 \
      category=sudo \
      severity=high \
      title="sudoers syntax errors detected" \
      description="The sudoers configuration failed syntax validation" \
      expected="Valid sudoers syntax" \
      actual="$output" \
      recommendation="Review the sudoers configuration using visudo"
  fi
}

check_sudoers_permissions() {
  local mode
  local owner
  local group

  if [[ ! -e "$SUDOERS_FILE" ]]; then
    finding \
      id=SUDO-002 \
      category=sudo \
      severity=info \
      title="$SUDOERS_FILE not found" \
      description="The main sudoers file could not be audited because it is absent" \
      expected="/etc/sudoers present when sudo is installed" \
      actual="File not found" \
      recommendation="Confirm whether sudo is installed and required"

    return 0
  fi

  mode="$(stat -c '%a' "$SUDOERS_FILE")"
  owner="$(stat -c '%U' "$SUDOERS_FILE")"
  group="$(stat -c '%G' "$SUDOERS_FILE")"

  if [[ "$mode" == "440" && "$owner" == "root" && "$group" == "root" ]]; then
    finding \
      id=SUDO-002 \
      category=sudo \
      severity=pass \
      title="/etc/sudoers permissions are correct" \
      description="The main sudoers file has the expected ownership and permissions" \
      expected="mode=440 owner=root group=root" \
      actual="mode=$mode owner=$owner group=$group" \
      recommendation="No action required"
  else
    finding \
      id=SUDO-002 \
      category=sudo \
      severity=high \
      title="/etc/sudoers permissions differ from expected" \
      description="Unexpected sudoers ownership or permissions may weaken sudo configuration protection" \
      expected="mode=440 owner=root group=root" \
      actual="mode=$mode owner=$owner group=$group" \
      recommendation="Review and correct the ownership and permissions of /etc/sudoers"
  fi
}

check_sudoers_d_permissions() {
  local file
  local mode
  local owner
  local group
  local issues=""
  local count=0

  if [[ ! -d /etc/sudoers.d ]]; then
    finding \
      id=SUDO-003 \
      category=sudo \
      severity=info \
      title="/etc/sudoers.d is not present" \
      description="No sudoers include directory was found" \
      expected="/etc/sudoers.d available when drop-in rules are used" \
      actual="Directory not found" \
      recommendation="No action required unless drop-in sudo rules are expected"

    return 0
  fi

  if [[ ! -r /etc/sudoers.d ]]; then
    finding \
      id=SUDO-003 \
      category=sudo \
      severity=info \
      title="sudoers.d files could not be audited" \
      description="The current process cannot read /etc/sudoers.d" \
      expected="Readable sudoers include directory for auditing" \
      actual="Permission denied" \
      recommendation="Run the audit with sufficient privileges"

    return 0
  fi

  while IFS= read -r file; do
    count=$((count + 1))

    mode="$(stat -c '%a' "$file")"
    owner="$(stat -c '%U' "$file")"
    group="$(stat -c '%G' "$file")"

    if [[ "$mode" != "440" || "$owner" != "root" || "$group" != "root" ]]; then
      issues+="$file mode=$mode owner=$owner group=$group; "
    fi
  done < <(
    find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null
  )

  if ((count == 0)); then
    finding \
      id=SUDO-003 \
      category=sudo \
      severity=info \
      title="No sudoers.d files found" \
      description="The sudoers include directory contains no regular files" \
      expected="Secure permissions on sudoers.d files when present" \
      actual="No files found" \
      recommendation="No action required"
  elif [[ -n "$issues" ]]; then
    finding \
      id=SUDO-003 \
      category=sudo \
      severity=high \
      title="sudoers.d permission issues detected" \
      description="One or more sudoers drop-in files have unexpected ownership or permissions" \
      expected="mode=440 owner=root group=root" \
      actual="$issues" \
      recommendation="Review and correct the affected sudoers.d files"
  else
    finding \
      id=SUDO-003 \
      category=sudo \
      severity=pass \
      title="sudoers.d file permissions are correct" \
      description="All discovered sudoers drop-in files have the expected ownership and permissions" \
      expected="mode=440 owner=root group=root" \
      actual="$count files validated" \
      recommendation="No action required"
  fi
}

check_nopasswd_rules() {
  local matches

  if [[ ! -r "$SUDOERS_FILE" ]]; then
    finding \
      id=SUDO-004 \
      category=sudo \
      severity=info \
      title="NOPASSWD rules could not be audited" \
      description="The current process cannot read /etc/sudoers" \
      expected="Readable sudoers configuration for auditing" \
      actual="Permission denied" \
      recommendation="Run the audit with sufficient privileges"

    return 0
  fi

  matches="$(
    grep -RIn --include='*' 'NOPASSWD' "$SUDOERS_FILE" /etc/sudoers.d 2>/dev/null |
      grep -Ev '^[^:]+:[0-9]+:[[:space:]]*#' ||
      true
  )"

  if [[ -z "$matches" ]]; then
    finding \
      id=SUDO-004 \
      category=sudo \
      severity=pass \
      title="No active NOPASSWD rules detected" \
      description="No uncommented sudo rules using NOPASSWD were found" \
      expected="No unnecessary passwordless sudo rules" \
      actual="No active NOPASSWD rules detected" \
      recommendation="No action required"
  else
    finding \
      id=SUDO-004 \
      category=sudo \
      severity=warn \
      title="Active NOPASSWD rules detected" \
      description="Passwordless sudo rules are active and should be reviewed for necessity" \
      expected="No unnecessary passwordless sudo rules" \
      actual="$matches" \
      recommendation="Review each NOPASSWD rule and keep only explicitly required privileges"
  fi
}

check_broad_sudo_rules() {
  local matches

  if [[ ! -r "$SUDOERS_FILE" ]]; then
    finding \
      id=SUDO-005 \
      category=sudo \
      severity=info \
      title="Broad sudo rules could not be audited" \
      description="The current process cannot read /etc/sudoers" \
      expected="Readable sudoers configuration for auditing" \
      actual="Permission denied" \
      recommendation="Run the audit with sufficient privileges"

    return 0
  fi

  matches="$(
    grep -RIn --include='*' -E 'ALL[[:space:]]*=[[:space:]]*\(ALL(:ALL)?\)[[:space:]]*ALL' \
      "$SUDOERS_FILE" /etc/sudoers.d 2>/dev/null |
      grep -Ev '^[^:]+:[0-9]+:[[:space:]]*#' ||
      true
  )"

  if [[ -z "$matches" ]]; then
    finding \
      id=SUDO-005 \
      category=sudo \
      severity=pass \
      title="No broad sudo rules detected" \
      description="No unrestricted ALL=(ALL) ALL style sudo rules were detected" \
      expected="Least-privilege sudo rules where practical" \
      actual="No broad rules detected" \
      recommendation="No action required"
  else
    finding \
      id=SUDO-005 \
      category=sudo \
      severity=info \
      title="Broad sudo rules detected" \
      description="Broad sudo privileges were found and may be intentional for administrative accounts" \
      expected="Least-privilege sudo rules where practical" \
      actual="$matches" \
      recommendation="Review broad sudo rules and confirm they are intentional"
  fi
}
