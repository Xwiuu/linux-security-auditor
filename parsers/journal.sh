#!/usr/bin/env bash

read_auth_journal() {
  local output

  output="$(
    journalctl \
      --no-pager \
      -o short-iso \
      SYSLOG_IDENTIFIER=sshd \
      2>/dev/null
  )"

  if [[ -z "$output" || "$output" == "-- No entries --" ]]; then
    printf '%s\n' '[INFO] JOURNAL-001 No SSH authentication events found'
    return 0
  fi

  printf '%s\n' "$output"
}
