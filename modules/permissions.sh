

check_file_permissions() {
  local file="$1"
  local expected_mode="$2"
  local expected_owner="$3"
  local expected_group="$4"

  local mode
  local owner
  local group

  mode="$(stat -c '%a' "$file")"
  owner="$(stat -c '%U' "$file")"
  group="$(stat -c '%G' "$file")"

  if [[ "$mode" == "$expected_mode" && "$owner" == "$expected_owner" && "$group" == "$expected_group" ]]; then
    printf '[PASS] %s permissions are correct\n' "$file"
  else
    printf '[HIGH] %s permissions differ from expected\n' "$file"
    printf '  Mode: %s (expected %s)\n' "$mode" "$expected_mode"
    printf '  Owner: %s (expected %s)\n' "$owner" "$expected_owner"
    printf '  Group: %s (expected %s)\n' "$group" "$expected_group"
  fi
}
check_shadow_permissions() {
  local file="$1"
  local mode
  local owner
  local group

  mode="$(stat -c '%a' "$file")"
  owner="$(stat -c '%U' "$file")"
  group="$(stat -c '%G' "$file")"

  if [[ "$owner" == "root" && "$mode" == "0" ]]; then
    printf '[PASS] %s is restricted to root\n' "$file"
  elif [[ "$owner" == "root" && "$mode" == "640" && "$group" == "shadow" ]]; then
    printf '[PASS] %s permissions are correct\n' "$file"
  else
    printf '[HIGH] %s permissions require review\n' "$file"
    printf '  Mode: %s\n' "$mode"
    printf '  Owner: %s\n' "$owner"
    printf '  Group: %s\n' "$group"
  fi
}
check_ssh_directory_permissions() {
  local home_dir="$1"
  local ssh_dir="$home_dir/.ssh"

  if [[ ! -d "$ssh_dir" ]]; then
    printf '[INFO] PERM-006 %s not found\n' "$ssh_dir"
    return 0
  fi

  check_file_permissions "$ssh_dir" 700 "$(stat -c '%U' "$home_dir")" "$(stat -c '%G' "$home_dir")"
}

check_authorized_keys_permissions() {
  local home_dir="$1"
  local auth_file="$home_dir/.ssh/authorized_keys"

  if [[ ! -f "$auth_file" ]]; then
    printf '[INFO] PERM-007 %s not found\n' "$auth_file"
    return 0
  fi

  check_file_permissions "$auth_file" 600 "$(stat -c '%U' "$home_dir")" "$(stat -c '%G' "$home_dir")"
}

get_target_home() {
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    getent passwd "$SUDO_USER" | cut -d: -f6
  else
    printf '%s\n' "$HOME"
  fi
}
