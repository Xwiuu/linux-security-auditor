#!/usr/bin/env bash

detect_firewall_backend() {
  if command -v firewall-cmd >/dev/null 2>&1; then
    printf '%s\n' 'firewalld'
  elif command -v nft >/dev/null 2>&1; then
    printf '%s\n' 'nftables'
  elif command -v iptables >/dev/null 2>&1; then
    printf '%s\n' 'iptables'
  elif command -v ufw >/dev/null 2>&1; then
    printf '%s\n' 'ufw'
  else
    printf '%s\n' 'none'
  fi
}

check_firewalld_status() {
  if firewall-cmd --state >/dev/null 2>&1; then
    printf '%s\n' '[PASS] FW-001 firewalld is running'
  else
    printf '%s\n' '[HIGH] FW-001 firewalld is not running'
  fi
}

check_active_zones() {
  local zones

  zones="$(firewall-cmd --get-active-zones 2>/dev/null || true)"

  if [[ -z "$zones" ]]; then
    printf '%s\n' '[WARN] FW-002 No active firewalld zones detected'
  else
    printf '%s\n' '[INFO] FW-002 Active firewalld zones:'
    printf '%s\n' "$zones"
  fi
}

check_active_zone_rules() {
  local zone
  local zone_output
  local status

  printf '%s\n' '[INFO] FW-003 Active zone rules:'

  while IFS= read -r zone; do
    zone_output=''
    status=0

    zone_output="$(firewall-cmd --zone="$zone" --list-all 2>&1)" || status=$?

    if ((status != 0)); then
      printf '[INFO] FW-003 Could not inspect zone %s\n' "$zone"
      printf '%s\n' "$zone_output"
      continue
    fi

    printf '\nZone: %s\n' "$zone"
    printf '%s\n' "$zone_output"
  done < <(
    firewall-cmd --get-active-zones 2>/dev/null |
      awk '/^[^[:space:]]/ { print $1 }'
  )
}

check_broad_port_ranges() {
  local zone
  local entry
  local range
  local protocol
  local start
  local end
  local span

  while IFS= read -r zone; do
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue

      range="${entry%/*}"
      protocol="${entry#*/}"

      if [[ "$range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        start="${BASH_REMATCH[1]}"
        end="${BASH_REMATCH[2]}"
        span=$((end - start + 1))

        if ((span >= 1000)); then
          printf '[WARN] FW-004 Broad port range in zone %s: %s/%s (%s ports)\n' \
            "$zone" "$range" "$protocol" "$span"
        fi
      fi
    done < <(
      firewall-cmd --zone="$zone" --list-ports |
        tr ' ' '\n'
    )
  done < <(
    firewall-cmd --get-active-zones |
      awk '/^[^[:space:]]/ { print $1 }'
  )
}
