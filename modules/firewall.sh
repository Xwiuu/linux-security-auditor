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

collect_firewall_state() {
  local zones_status=0
  local zone
  local zone_output
  local status
  local entry
  local range
  local protocol
  local start
  local end
  local span
  local interfaces
  local line

  FW_COLLECTED=1
  FW_BACKEND="none"
  FW_STATE_STATUS=0
  FW_STATE_OUTPUT=""
  FW_ZONES_PARSE_OK=0
  FW_ZONE_NAMES=()
  FW_ZONES_SUMMARY=""
  FW_ZONES_INSPECTED=0
  FW_ZONE_RULES=()
  FW_ZONE_FAILURES=()
  FW_BROAD_RANGES=()
  FW_PORTS_ZONES_ATTEMPTED=0
  FW_PORTS_ZONES_OK=0

  if ! command -v firewall-cmd >/dev/null 2>&1; then
    return 0
  fi

  FW_BACKEND="firewalld"

  FW_STATE_OUTPUT="$(firewall-cmd --state 2>&1)" || FW_STATE_STATUS=$?

  FW_ZONES_RAW="$(firewall-cmd --get-active-zones 2>/dev/null)" || zones_status=$?

  ((zones_status == 0)) || return 0

  FW_ZONES_PARSE_OK=1

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    if [[ "$line" != [[:space:]]* ]]; then
      zone="${line%% *}"
      FW_ZONE_NAMES+=("$zone")
      FW_ZONES_SUMMARY+="$zone"
      FW_ZONES_SUMMARY+=": "

    elif [[ "$line" == *interfaces:* ]]; then
      interfaces="${line#*interfaces:}"
      interfaces="${interfaces#"${interfaces%%[![:space:]]*}"}"
      FW_ZONES_SUMMARY+="$interfaces"
      FW_ZONES_SUMMARY+="; "
    fi
  done <<<"$FW_ZONES_RAW"

  FW_ZONES_SUMMARY="${FW_ZONES_SUMMARY%; }"

  for zone in ${FW_ZONE_NAMES[@]+"${FW_ZONE_NAMES[@]}"}; do
    zone_output=""
    status=0

    zone_output="$(firewall-cmd --zone="$zone" --list-all 2>&1)" || status=$?

    if ((status != 0)); then
      FW_ZONE_FAILURES+=("$zone: unavailable (status=$status)")
    else
      FW_ZONES_INSPECTED=$((FW_ZONES_INSPECTED + 1))
      FW_ZONE_RULES+=("$zone")
    fi

    FW_PORTS_ZONES_ATTEMPTED=$((FW_PORTS_ZONES_ATTEMPTED + 1))
    status=0
    zone_output="$(firewall-cmd --zone="$zone" --list-ports 2>&1)" || status=$?

    if ((status != 0)); then
      continue
    fi

    FW_PORTS_ZONES_OK=$((FW_PORTS_ZONES_OK + 1))

    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue

      range="${entry%/*}"
      protocol="${entry#*/}"

      if [[ "$range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        start="${BASH_REMATCH[1]}"
        end="${BASH_REMATCH[2]}"
        span=$((end - start + 1))

        if ((span >= 1000)); then
          FW_BROAD_RANGES+=("$zone: $range/$protocol ($span ports)")
        fi
      fi
    done < <(tr ' ' '\n' <<<"$zone_output")
  done

  return 0
}

ensure_firewall_state() {
  if [[ "${FW_COLLECTED:-0}" -ne 1 ]]; then
    collect_firewall_state
  fi
}

reset_firewall_state() {
  FW_COLLECTED=0
}

check_firewalld_status() {
  ensure_firewall_state

  if [[ "$FW_BACKEND" == "none" ]]; then
    finding \
      id=FW-001 \
      category=firewall \
      severity=info \
      title="Firewall status could not be audited" \
      description="firewall-cmd is not available on this system" \
      expected="A supported firewall backend available for inspection" \
      actual="firewall-cmd not found" \
      recommendation="Confirm which firewall backend is in use"

  elif ((FW_STATE_STATUS == 0)) && [[ "$FW_STATE_OUTPUT" == "running" ]]; then
    finding \
      id=FW-001 \
      category=firewall \
      severity=pass \
      title="firewalld is running" \
      description="The firewalld service is active" \
      expected="An active firewall service" \
      actual="running" \
      recommendation="No action required"

  elif grep -qiE 'not running|not active|stopped' <<<"$FW_STATE_OUTPUT"; then
    finding \
      id=FW-001 \
      category=firewall \
      severity=medium \
      title="firewalld is not running" \
      description="The firewall service is available but not active" \
      expected="An active firewall service" \
      actual="${FW_STATE_OUTPUT:-not running}" \
      recommendation="Review whether the host requires an active firewall"

  else
    finding \
      id=FW-001 \
      category=firewall \
      severity=info \
      title="Firewall status could not be audited" \
      description="firewall-cmd failed while checking firewall state" \
      expected="Readable firewall state" \
      actual="firewall-cmd exited with status $FW_STATE_STATUS" \
      recommendation="Verify firewalld availability and permissions"
  fi
}

check_active_zones() {
  ensure_firewall_state

  if [[ "$FW_BACKEND" == "none" ]]; then
    finding \
      id=FW-002 \
      category=firewall \
      severity=info \
      title="Active zones could not be inventoried" \
      description="firewalld is not available to list active zones" \
      expected="Readable list of active firewall zones" \
      actual="firewall-cmd not found" \
      recommendation="Confirm which firewall backend is in use"

  elif [[ "$FW_ZONES_PARSE_OK" -ne 1 ]]; then
    finding \
      id=FW-002 \
      category=firewall \
      severity=info \
      title="Active zones could not be inventoried" \
      description="firewall-cmd failed while listing active zones" \
      expected="Readable list of active firewall zones" \
      actual="firewall-cmd --get-active-zones failed" \
      recommendation="Verify firewalld availability and permissions"

  elif ((${#FW_ZONE_NAMES[@]} == 0)); then
    finding \
      id=FW-002 \
      category=firewall \
      severity=info \
      title="No active firewalld zones detected" \
      description="firewalld reported no active zones" \
      expected="Readable list of active firewall zones" \
      actual="No active zones" \
      recommendation="Confirm whether firewalld zones are expected on this host"

  else
    finding \
      id=FW-002 \
      category=firewall \
      severity=info \
      title="Active firewalld zones detected" \
      description="firewalld reports active zones with bound interfaces" \
      expected="Readable list of active firewall zones" \
      actual="$FW_ZONES_SUMMARY" \
      recommendation="Review whether each active zone and interface is expected"
  fi
}

check_active_zone_rules() {
  local summary
  local item
  local limit

  ensure_firewall_state

  if [[ "$FW_BACKEND" == "none" ]]; then
    finding \
      id=FW-003 \
      category=firewall \
      severity=info \
      title="Firewall zone rules could not be audited" \
      description="firewall-cmd is not available to inspect zone rules" \
      expected="Readable rules for each active zone" \
      actual="firewall-cmd not found" \
      recommendation="Confirm which firewall backend is in use"

    return 0
  fi

  if [[ "$FW_ZONES_PARSE_OK" -ne 1 ]]; then
    finding \
      id=FW-003 \
      category=firewall \
      severity=info \
      title="Firewall zone rules could not be audited" \
      description="firewall-cmd failed while listing active zones, so zone rules could not be inspected" \
      expected="Readable rules for each active zone" \
      actual="firewall-cmd --get-active-zones failed" \
      recommendation="Verify firewalld availability and permissions"

    return 0
  fi

  if ((${#FW_ZONE_NAMES[@]} == 0)); then
    finding \
      id=FW-003 \
      category=firewall \
      severity=info \
      title="No active zones to inspect" \
      description="There are no active firewalld zones to inspect" \
      expected="Readable rules for each active zone" \
      actual="No active zones" \
      recommendation="Confirm whether firewalld zones are expected on this host"

    return 0
  fi

  summary=""

  for item in ${FW_ZONE_RULES[@]+"${FW_ZONE_RULES[@]}"}; do
    summary+="$item; "
  done

  for item in ${FW_ZONE_FAILURES[@]+"${FW_ZONE_FAILURES[@]}"}; do
    summary+="$item; "
  done

  summary="${summary%; }"

  if ((FW_ZONES_INSPECTED == 0)); then
    finding \
      id=FW-003 \
      category=firewall \
      severity=info \
      title="Firewall zone rules could not be fully audited" \
      description="No active zone returned readable rules" \
      expected="Readable rules for each active zone" \
      actual="$summary" \
      recommendation="Verify firewalld permissions for zone inspection"

  else
    limit=0

    for item in ${FW_ZONE_FAILURES[@]+"${FW_ZONE_FAILURES[@]}"}; do
      limit=$((limit + 1))

      if ((limit > 20)); then
        summary+=" ... truncated"
        break
      fi
    done

    finding \
      id=FW-003 \
      category=firewall \
      severity=info \
      title="Firewall zone rules collected" \
      description="Zone rules were collected for inspectable zones; uninspectable zones are listed" \
      expected="Readable rules for each active zone" \
      actual="$summary" \
      recommendation="Review zone rules and investigate zones that could not be inspected"
  fi
}

check_broad_port_ranges() {
  local summary
  local item
  local limit=0

  ensure_firewall_state

  if [[ "$FW_BACKEND" == "none" || "$FW_ZONES_PARSE_OK" -ne 1 ]] ||
    ((${#FW_ZONE_NAMES[@]} > 0 && FW_PORTS_ZONES_OK == 0)); then
    finding \
      id=FW-004 \
      category=firewall \
      severity=info \
      title="Broad firewall ranges could not be fully audited" \
      description="Zone port lists could not be read, so broad ranges could not be confirmed" \
      expected="Readable zone port lists for broad range detection" \
      actual="Zone port inspection unavailable" \
      recommendation="Verify firewalld availability and permissions"

    return 0
  fi

  if ((${#FW_BROAD_RANGES[@]} == 0)); then
    finding \
      id=FW-004 \
      category=firewall \
      severity=pass \
      title="No broad firewall port ranges detected" \
      description="No zone exposes a port range of 1000 ports or more" \
      expected="No unnecessarily broad firewall port ranges" \
      actual="No broad port ranges detected" \
      recommendation="No action required"

    return 0
  fi

  summary=""

  for item in "${FW_BROAD_RANGES[@]}"; do
    limit=$((limit + 1))

    if ((limit > 20)); then
      summary+="... truncated"
      break
    fi

    summary+="$item; "
  done

  finding \
    id=FW-004 \
    category=firewall \
    severity=medium \
    title="Broad firewall port ranges detected" \
    description="One or more zones allow port ranges of 1000 ports or more" \
    expected="No unnecessarily broad firewall port ranges" \
    actual="$summary" \
    recommendation="Review each broad range and narrow it to the ports actually required"
}
