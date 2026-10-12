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

get_os_name() {
  local NAME=""

  if [[ -r "$OS_RELEASE_FILE" ]]; then
    # shellcheck source=/etc/os-release
    source "$OS_RELEASE_FILE"
  fi

  printf '%s\n' "${NAME:-Unknown}"
}

get_os_version() {
  local VERSION=""

  if [[ -r "$OS_RELEASE_FILE" ]]; then
    # shellcheck source=/etc/os-release
    source "$OS_RELEASE_FILE"
  fi

  printf '%s\n' "${VERSION:-Unknown}"
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
