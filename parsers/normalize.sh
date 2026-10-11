#!/usr/bin/env bash

normalize_failed_password_event() {
  local line="$1"
  local timestamp
  local user
  local ip

  timestamp="$(awk '{ print $1 }' <<< "$line")"

  user="$(
    sed -nE \
      's/.*Failed password for (invalid user )?([^ ]+) from .*/\2/p' \
      <<< "$line"
  )"

  ip="$(
    sed -nE \
      's/.* from ([0-9a-fA-F:.]+) port .*/\1/p' \
      <<< "$line"
  )"

  printf '%s|AUTH_FAILURE|%s|%s|password\n' \
    "$timestamp" "$user" "$ip"
}

normalize_accepted_password_event() {
  local line="$1"
  local timestamp
  local user
  local ip

  timestamp="$(awk '{ print $1 }' <<< "$line")"

  user="$(
    sed -nE \
      's/.*Accepted password for ([^ ]+) from .*/\1/p' \
      <<< "$line"
  )"

  ip="$(
    sed -nE \
      's/.* from ([0-9a-fA-F:.]+) port .*/\1/p' \
      <<< "$line"
  )"

  printf '%s|AUTH_SUCCESS|%s|%s|password\n' \
    "$timestamp" "$user" "$ip"
}

normalize_accepted_publickey_event() {
  local line="$1"
  local timestamp
  local user
  local ip

  timestamp="$(awk '{ print $1 }' <<< "$line")"

  user="$(
    sed -nE \
      's/.*Accepted publickey for ([^ ]+) from .*/\1/p' \
      <<< "$line"
  )"

  ip="$(
    sed -nE \
      's/.* from ([0-9a-fA-F:.]+) port .*/\1/p' \
      <<< "$line"
  )"

  printf '%s|AUTH_SUCCESS|%s|%s|publickey\n' \
    "$timestamp" "$user" "$ip"
}

normalize_ssh_event() {
  local line="$1"

  case "$line" in
    *"Failed password"*)
      normalize_failed_password_event "$line"
      ;;
    *"Accepted password"*)
      normalize_accepted_password_event "$line"
      ;;
    *"Accepted publickey"*)
      normalize_accepted_publickey_event "$line"
      ;;

    *)
      return 1
      ;;
  esac
}
