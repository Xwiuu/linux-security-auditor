check_file_permissions() {
  local id="$1"
  local file="$2"
  local expected_mode="$3"
  local expected_owner="$4"
  local expected_group="$5"

  local mode
  local owner
  local group

  if [[ ! -e "$file" ]]; then
    finding \
      id="$id" \
      category=permissions \
      severity=info \
      title="$file not found" \
      description="The expected file was not found and could not be audited" \
      expected="File present with expected ownership and permissions" \
      actual="File not found" \
      recommendation="Review whether this file should exist on the system"

    return 0
  fi

  mode="$(stat -c '%a' "$file" 2>/dev/null || true)"
  owner="$(stat -c '%U' "$file" 2>/dev/null || true)"
  group="$(stat -c '%G' "$file" 2>/dev/null || true)"

  if [[ -z "$mode" || -z "$owner" || -z "$group" ]]; then
    finding \
      id="$id" \
      category=permissions \
      severity=info \
      title="$file could not be audited" \
      description="File metadata could not be read" \
      expected="Readable metadata for permission auditing" \
      actual="Metadata unavailable" \
      recommendation="Run the audit with sufficient privileges"

    return 0
  fi

  if [[ "$mode" == "$expected_mode" &&
        "$owner" == "$expected_owner" &&
        "$group" == "$expected_group" ]]; then
    finding \
      id="$id" \
      category=permissions \
      severity=pass \
      title="$file permissions are correct" \
      description="The file has the expected ownership and permissions" \
      expected="mode=$expected_mode owner=$expected_owner group=$expected_group" \
      actual="mode=$mode owner=$owner group=$group" \
      recommendation="No action required"
  else
    finding \
      id="$id" \
      category=permissions \
      severity=high \
      title="$file permissions differ from expected" \
      description="The file ownership or permissions differ from the expected secure configuration" \
      expected="mode=$expected_mode owner=$expected_owner group=$expected_group" \
      actual="mode=$mode owner=$owner group=$group" \
      recommendation="Review and correct the file ownership and permissions"
  fi
}


check_shadow_permissions() {
  local id="$1"
  local file="$2"

  local mode
  local owner
  local group

  if [[ ! -e "$file" ]]; then
    finding \
      id="$id" \
      category=permissions \
      severity=info \
      title="$file not found" \
      description="The shadow database file was not found" \
      expected="Shadow database file present and restricted" \
      actual="File not found" \
      recommendation="Review whether this file should exist on the system"

    return 0
  fi

  mode="$(stat -c '%a' "$file" 2>/dev/null || true)"
  owner="$(stat -c '%U' "$file" 2>/dev/null || true)"
  group="$(stat -c '%G' "$file" 2>/dev/null || true)"

  if [[ -z "$mode" || -z "$owner" || -z "$group" ]]; then
    finding \
      id="$id" \
      category=permissions \
      severity=info \
      title="$file could not be audited" \
      description="Shadow file metadata could not be read" \
      expected="Readable metadata for permission auditing" \
      actual="Metadata unavailable" \
      recommendation="Run the audit with sufficient privileges"

    return 0
  fi

  if [[ "$owner" == "root" && "$mode" == "0" ]]; then
    finding \
      id="$id" \
      category=permissions \
      severity=pass \
      title="$file is restricted to root" \
      description="The shadow file uses a restrictive root-only permission model" \
      expected="Restricted shadow file access" \
      actual="mode=$mode owner=$owner group=$group" \
      recommendation="No action required"

  elif [[ "$owner" == "root" &&
          "$mode" == "640" &&
          "$group" == "shadow" ]]; then
    finding \
      id="$id" \
      category=permissions \
      severity=pass \
      title="$file permissions are correct" \
      description="The shadow file uses the expected root:shadow permission model" \
      expected="mode=640 owner=root group=shadow or stricter equivalent" \
      actual="mode=$mode owner=$owner group=$group" \
      recommendation="No action required"

  else
    finding \
      id="$id" \
      category=permissions \
      severity=high \
      title="$file permissions require review" \
      description="The shadow file permissions do not match an accepted restricted configuration" \
      expected="mode=000 owner=root or mode=640 owner=root group=shadow" \
      actual="mode=$mode owner=$owner group=$group" \
      recommendation="Review and restrict access to the shadow file"
  fi
}


check_ssh_directory_permissions() {
  local home_dir="$1"
  local ssh_dir="$home_dir/.ssh"

  if [[ ! -d "$ssh_dir" ]]; then
    finding \
      id=PERM-006 \
      category=permissions \
      severity=info \
      title=".ssh directory not found" \
      description="No SSH directory exists for the target user" \
      expected="Secure .ssh permissions when the directory exists" \
      actual="$ssh_dir not found" \
      recommendation="No action required unless SSH keys are expected"

    return 0
  fi

  check_file_permissions \
    PERM-006 \
    "$ssh_dir" \
    700 \
    "$(stat -c '%U' "$home_dir")" \
    "$(stat -c '%G' "$home_dir")"
}


check_authorized_keys_permissions() {
  local home_dir="$1"
  local auth_file="$home_dir/.ssh/authorized_keys"

  if [[ ! -f "$auth_file" ]]; then
    finding \
      id=PERM-007 \
      category=permissions \
      severity=info \
      title="authorized_keys not found" \
      description="No authorized_keys file exists for the target user" \
      expected="Secure authorized_keys permissions when the file exists" \
      actual="$auth_file not found" \
      recommendation="No action required unless public-key authentication is expected"

    return 0
  fi

  check_file_permissions \
    PERM-007 \
    "$auth_file" \
    600 \
    "$(stat -c '%U' "$home_dir")" \
    "$(stat -c '%G' "$home_dir")"
}


get_target_home() {
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    getent passwd "$SUDO_USER" | cut -d: -f6
  else
    printf '%s\n' "$HOME"
  fi
}
