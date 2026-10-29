#!/usr/bin/env bash

OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"

get_hostname() {
  hostname
}

get_kernel() {
  uname -r
}

get_architecture() {
  uname -m
}

_get_os_release_value() {
  local target_key="$1"
  local file="${OS_RELEASE_FILE:-/etc/os-release}"

  [[ -r "$file" ]] || return 1

  local line key val inner content slashes
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Strip leading and trailing whitespace
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"

    # Skip comments and empty lines
    [[ -z "$line" || "$line" == \#* ]] && continue

    # Must contain an '=' assignment operator
    [[ "$line" == *"="* ]] || continue

    key="${line%%=*}"
    val="${line#*=}"

    # Trim whitespace around key
    key="${key%"${key##*[![:space:]]}"}"
    key="${key#"${key%%[![:space:]]*}"}"

    [[ "$key" == "$target_key" ]] || continue

    if [[ "$val" == \"* ]]; then
      # Double-quoted string: must end with quote and have balanced quotes
      if [[ "$val" == *\" && "${#val}" -ge 2 ]]; then
        inner="${val#\"}"
        content="${inner%\"}"
        slashes="${content##*[!\\]}"
        if ((${#slashes} % 2 != 0)); then
          # Trailing quote was escaped, meaning the string is unclosed
          return 1
        fi
        val="$content"
        # Unescape standard os-release escapes: \", \\, \$, \`
        val="${val//\\\"/\"}"
        val="${val//\\\\/\\}"
        val="${val//\\\$/\$}"
        val="${val//\\\`/\\\`}"
      else
        # Malformed quoted string: unclosed quote
        return 1
      fi
    elif [[ "$val" == \'* ]]; then
      # Single-quoted string: must end with quote
      if [[ "$val" == *\' && "${#val}" -ge 2 ]]; then
        val="${val#\'}"
        val="${val%\'}"
      else
        # Malformed single-quoted string: unclosed quote
        return 1
      fi
    else
      # Unquoted value: os-release spec requires unquoted values to contain no whitespace
      if [[ "$val" =~ [[:space:]] ]]; then
        return 1
      fi
    fi

    [[ -n "$val" ]] || return 1

    printf '%s\n' "$val"
    return 0
  done <"$file"

  return 1
}

get_os_name() {
  local val
  if val="$(_get_os_release_value "NAME")"; then
    printf '%s\n' "$val"
  else
    printf '%s\n' 'Unknown'
  fi
}

get_os_version() {
  local val
  if val="$(_get_os_release_value "VERSION")"; then
    printf '%s\n' "$val"
  else
    printf '%s\n' 'Unknown'
  fi
}

get_init_system() {
  if command -v systemctl >/dev/null 2>&1; then
    printf '%s\n' 'systemd'
  else
    printf '%s\n' 'unknown'
  fi
}

get_package_manager() {
  if command -v dnf >/dev/null 2>&1; then
    printf '%s\n' 'dnf'
  elif command -v apt >/dev/null 2>&1; then
    printf '%s\n' 'apt'
  elif command -v pacman >/dev/null 2>&1; then
    printf '%s\n' 'pacman'
  else
    printf '%s\n' 'unknown'
  fi
}

get_uptime() {
  uptime -p
}
