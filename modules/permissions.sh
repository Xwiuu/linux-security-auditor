#!/usr/bin/env bash

# Security Note:
# Detecting symbolic links via [[ -L ]] inspects current filesystem state at check time,
# but does not eliminate time-of-check to time-of-use (TOCTOU) races if an adversary
# holds write access to parent directories. Kernel mechanisms (such as fs.protected_symlinks)
# and descriptor-based operations are required for OS-enforced TOCTOU guarantees.
# This module explicitly avoids following unexpected symbolic links at critical security paths.

check_file_permissions() {
  local id="$1"
  local file="$2"
  local expected_mode="$3"
  local expected_owner="$4"
  local expected_group="$5"

  local mode
  local owner
  local group

  # FIX-03: Detect symbolic links before existence/dereferencing checks
  if [[ -L "$file" ]]; then
    local target
    target="$(readlink "$file" 2>/dev/null || printf '%s' 'unknown')"
    finding \
      id="$id" \
      category=permissions \
      severity=high \
      title="$file is a symbolic link" \
      description="The critical security file is a symbolic link, which can permit redirection or unauthorized tampering" \
      expected="Regular file with mode=$expected_mode owner=$expected_owner group=$expected_group" \
      actual="Symbolic link pointing to $target" \
      recommendation="Replace the symbolic link with a regular file configured with appropriate permissions"

    return 0
  fi

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

  # Unexpected non-regular special file (FIFO, socket, device)
  if [[ ! -f "$file" && ! -d "$file" ]]; then
    finding \
      id="$id" \
      category=permissions \
      severity=high \
      title="$file has unexpected file type" \
      description="The audited path is neither a regular file nor a directory" \
      expected="Regular file or directory with expected ownership and permissions" \
      actual="Non-regular special file" \
      recommendation="Review and replace the special file with the expected configuration"

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

  # FIX-03: Critical security boundary check - shadow file must never be a symbolic link
  if [[ -L "$file" ]]; then
    local target
    target="$(readlink "$file" 2>/dev/null || printf '%s' 'unknown')"
    finding \
      id="$id" \
      category=permissions \
      severity=critical \
      title="$file is a symbolic link" \
      description="The shadow database file is a symbolic link, presenting a critical security risk" \
      expected="Regular file restricted to root (mode=000 or mode=640 root:shadow)" \
      actual="Symbolic link pointing to $target" \
      recommendation="Replace the symbolic link with a secure regular shadow file"

    return 0
  fi

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

  if [[ ! -f "$file" ]]; then
    finding \
      id="$id" \
      category=permissions \
      severity=critical \
      title="$file is not a regular file" \
      description="The shadow database file path is not a regular file" \
      expected="Regular file restricted to root" \
      actual="Non-regular file type" \
      recommendation="Ensure the shadow file is a regular file"

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

  # FIX-03: Detect symbolic links for .ssh directory before traversal
  if [[ -L "$ssh_dir" ]]; then
    local target
    target="$(readlink "$ssh_dir" 2>/dev/null || printf '%s' 'unknown')"
    finding \
      id=PERM-006 \
      category=permissions \
      severity=high \
      title="$ssh_dir is a symbolic link" \
      description="The .ssh configuration directory is a symbolic link, which can permit redirection to unauthorized keys" \
      expected="Regular directory with mode=700" \
      actual="Symbolic link pointing to $target" \
      recommendation="Replace the symbolic link with a secure local directory"

    return 0
  fi

  if [[ ! -e "$ssh_dir" ]]; then
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

  if [[ ! -d "$ssh_dir" ]]; then
    finding \
      id=PERM-006 \
      category=permissions \
      severity=high \
      title="$ssh_dir is not a directory" \
      description="The .ssh path is not a directory" \
      expected="Directory with mode=700" \
      actual="Non-directory file present" \
      recommendation="Ensure .ssh is a directory with mode 700"

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

  # FIX-03: Detect symbolic links for authorized_keys before dereference
  if [[ -L "$auth_file" ]]; then
    local target
    target="$(readlink "$auth_file" 2>/dev/null || printf '%s' 'unknown')"
    finding \
      id=PERM-007 \
      category=permissions \
      severity=high \
      title="$auth_file is a symbolic link" \
      description="The authorized_keys file is a symbolic link, which can permit unauthorized key injection" \
      expected="Regular file with mode=600" \
      actual="Symbolic link pointing to $target" \
      recommendation="Replace the symbolic link with a regular file containing authorized public keys"

    return 0
  fi

  if [[ ! -e "$auth_file" ]]; then
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

  if [[ ! -f "$auth_file" ]]; then
    finding \
      id=PERM-007 \
      category=permissions \
      severity=high \
      title="$auth_file is not a regular file" \
      description="The authorized_keys path is not a regular file" \
      expected="Regular file with mode=600" \
      actual="Non-regular file type" \
      recommendation="Ensure authorized_keys is a regular file with mode 600"

    return 0
  fi

  check_file_permissions \
    PERM-007 \
    "$auth_file" \
    600 \
    "$(stat -c '%U' "$home_dir")" \
    "$(stat -c '%G' "$home_dir")"
}

audit_ssh_home_permissions() {
  local target_home

  if ! target_home="$(get_target_home)"; then
    finding \
      id=PERM-006 \
      category=permissions \
      severity=info \
      title="Target user home could not be resolved" \
      description="The target account could not be found in the passwd database" \
      expected="Resolvable target user account" \
      actual="User lookup failed" \
      recommendation="Verify that the target account still exists"

    finding \
      id=PERM-007 \
      category=permissions \
      severity=info \
      title="authorized_keys could not be audited" \
      description="The target home directory is unknown, so authorized_keys could not be located" \
      expected="Resolvable target user account for authorized_keys auditing" \
      actual="User lookup failed" \
      recommendation="Verify that the target account still exists"

    return 0
  fi

  check_ssh_directory_permissions "$target_home"
  check_authorized_keys_permissions "$target_home"
  return 0
}

get_target_home() {
  local username
  local passwd_entry

  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    username="$SUDO_USER"
  else
    username="${USER:-$(id -un)}"
  fi

  if ! passwd_entry="$(getent passwd "$username")"; then
    return 1
  fi

  printf '%s\n' "$passwd_entry" | cut -d: -f6
}
