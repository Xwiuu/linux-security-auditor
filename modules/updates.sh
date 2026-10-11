#!/usr/bin/env bash

check_pending_updates() {
  local count

  count="$(
    dnf check-update --quiet 2>/dev/null |
      awk '
        /^[[:alnum:]_.+-]+[[:space:]]+[[:alnum:]_.:+-]+[[:space:]]+/ {
          count++
        }
        END {
          print count + 0
        }
      '
  )"

  if (( count == 0 )); then
    printf '%s\n' '[PASS] UPDATE-001 No pending package updates detected'
  else
    printf '[INFO] UPDATE-001 Pending package updates: %s\n' "$count"
  fi
}

check_security_updates() {
  local count

  count="$(
    LC_ALL=C dnf updateinfo list --security --updates 2>/dev/null |
      awk '
        NR == 1 && $1 == "Name" { next }
        /^[[:alnum:]_.+-]+[[:space:]]+/ {
          count++
        }
        END {
          print count + 0
        }
      '
  )"

  if (( count == 0 )); then
    printf '%s\n' '[PASS] UPDATE-002 No pending security updates detected'
  else
    printf '[WARN] UPDATE-002 Pending security updates: %s\n' "$count"
  fi
}
