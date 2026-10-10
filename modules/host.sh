#!/usr/bin/env bash

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
  source /etc/os-release
  printf '%s\n' "$NAME"
}

get_os_version() {
  source /etc/os-release
  printf '%s\n' "$VERSION"
}

get_init_system() {
  if command -v systemctl>/dev/null 2>&1; then
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


