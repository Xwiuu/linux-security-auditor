#!/usr/bin/env bash

check_pending_updates() {
  local output
  local status=0

  output="$(dnf check-update --quiet 2>&1)" || status=$?

  case "$status" in
    0)
      printf '%s\n' '[PASS] UPDATE-001 No pending package updates'
      ;;
    100)
      printf '%s\n' '[INFO] UPDATE-001 Pending package updates detected'
      printf '%s\n' "$output"
      ;;
    *)
      printf '%s\n' '[INFO] UPDATE-001 Package update status could not be audited'
      printf '%s\n' "$output"
      ;;
  esac
}

check_security_updates() {
  local output
  local status=0
  local count

  output="$(LC_ALL=C dnf updateinfo list --security --updates 2>&1)" || status=$?

  if ((status != 0)); then
    printf '%s\n' '[INFO] UPDATE-002 Security update status could not be audited'
    printf '%s\n' "$output"
    return 0
  fi

  count="$(
    awk '
        NR == 1 && $1 == "Name" { next }
        /^[[:alnum:]_.+-]+[[:space:]]+/ {
          count++
        }
        END {
          print count + 0
        }
      ' <<<"$output"
  )"

  if ((count == 0)); then
    printf '%s\n' '[PASS] UPDATE-002 No pending security updates detected'
  else
    printf '[WARN] UPDATE-002 Pending security updates: %s\n' "$count"
  fi
}
