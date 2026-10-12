#!/usr/bin/env bash

read_auth_journal() {
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
    printf '%s\n' '[INFO] JOURNAL-001 SSH journal could not be read'
    printf '%s\n' "$output"
    return 0
  fi

  if [[ -z "$output" || "$output" == "-- No entries --" ]]; then
    printf '%s\n' '[INFO] JOURNAL-001 No SSH authentication events found'
    return 0
  fi

  printf '%s\n' "$output"
}
