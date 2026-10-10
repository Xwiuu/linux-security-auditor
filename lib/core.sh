#!/usr/bin/env bash

show_banner() {
  printf '%s\n' 'Linux Security Auditor'
}

die() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}
