#!/usr/bin/env bash

parse_ssh_auth_events() {
  local output
  local status=0

  output="$(
    journalctl \
      --no-pager \
      -o short-iso \
      SYSLOG_IDENTIFIER=sshd \
      2>&1
  )" || status=$?

  if ((status != 0)); then
    printf '%s\n' '[INFO] SSHLOG-001 SSH journal could not be read'
    printf '%s\n' "$output"
    return 0
  fi

  if [[ -z "$output" || "$output" == "-- No entries --" ]]; then
    printf '%s\n' '[INFO] SSHLOG-001 No SSH authentication events to parse'
    return 0
  fi

  grep -E \
    'Failed password|Accepted password|Accepted publickey|Invalid user' \
    <<<"$output" || true
}
