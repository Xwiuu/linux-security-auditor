#!/usr/bin/env bash

parse_ssh_auth_events() {
  local output

  output="$(
    journalctl \
      --no-pager \
      -o short-iso \
      SYSLOG_IDENTIFIER=sshd \
      2>/dev/null
  )"

  if [[ -z "$output" || "$output" == "-- No entries --" ]]; then
    printf '%s\n' '[INFO] SSHLOG-001 No SSH authentication events to parse'
    return 0
  fi

  grep -E \
    'Failed password|Accepted password|Accepted publickey|Invalid user' \
    <<< "$output" || true
}
