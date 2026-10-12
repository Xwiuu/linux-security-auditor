#!/usr/bin/env bash

collect_listening_sockets() {
  local output
  local status=0
  local line
  local proto
  local state
  local local_address
  local process
  local addr_no_port
  local iface

  PORTS_LOCAL=()
  PORTS_LAN=()
  PORTS_VPN=()
  PORTS_DOCKER=()
  PORTS_MULTICAST=()
  PORTS_EXPOSED=()
  PORTS_EXPOSED_TCP=()

  output="$(ss -tulpn 2>/dev/null)" || status=$?

  ((status == 0)) || return "$status"

  while IFS= read -r line; do
    [[ "$line" == Netid* ]] && continue
    [[ -z "$line" ]] && continue

    proto="$(awk '{ print $1 }' <<<"$line")"
    state="$(awk '{ print $2 }' <<<"$line")"
    local_address="$(awk '{ print $5 }' <<<"$line")"
    process="$(awk '{ for (i = 7; i <= NF; i++) printf "%s ", $i }' <<<"$line")"
    process="${process%; }"
    process="${process% }"

    addr_no_port="${local_address%:*}"
    iface=""
    [[ "$addr_no_port" == *%* ]] && iface="${addr_no_port#*%}"

    if [[ "$addr_no_port" == "127."* || "$addr_no_port" == "[::1]" || "$addr_no_port" == "::ffff:127."* ]]; then
      PORTS_LOCAL+=("$local_address $process")
    elif [[ "$addr_no_port" == "224."* || "$addr_no_port" == "ff"* || "$addr_no_port" == "[ff"* ]]; then
      PORTS_MULTICAST+=("$local_address $process")
    elif [[ "$iface" == docker* || "$iface" == br-* || "$iface" == virbr* || "$iface" == veth* ]] || [[ "$addr_no_port" =~ ^172\.(1[6-9]|2[0-9]|3[01])\.0\.1$ ]]; then
      PORTS_DOCKER+=("$local_address $process")
    elif [[ "$addr_no_port" =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]] || [[ "$addr_no_port" == "[fd7a:115c:a1e0::"* ]] || [[ "$iface" == tailscale* || "$iface" == zt* ]]; then
      PORTS_VPN+=("$local_address $process")
    elif [[ "$addr_no_port" == "192.168."* || "$addr_no_port" == "10."* || "$addr_no_port" == "172.1"[6-9].* || "$addr_no_port" == "172.2"[0-9].* || "$addr_no_port" == "172.3"[0-1].* || "$addr_no_port" == "[fd"* ]]; then
      PORTS_LAN+=("$local_address $process")
    else
      PORTS_EXPOSED+=("$local_address $process")

      if [[ "$proto" == "tcp" && "$state" == "LISTEN" ]]; then
        PORTS_EXPOSED_TCP+=("$local_address $process")
      fi
    fi
  done <<<"$output"

  return 0
}

summarize_listening_ports() {
  local status=0
  local id
  local title
  local description
  local summary
  local item
  local limit

  collect_listening_sockets || status=$?

  if ((status != 0)); then
    for id in PORT-001 PORT-002 PORT-003 PORT-004 PORT-005 PORT-006; do
      case "$id" in
        PORT-001)
          title="Local listeners could not be inventoried"
          description="The socket listing could not be read to inventory local listeners"
          ;;
        PORT-002)
          title="LAN listeners could not be inventoried"
          description="The socket listing could not be read to inventory LAN listeners"
          ;;
        PORT-003)
          title="VPN listeners could not be inventoried"
          description="The socket listing could not be read to inventory VPN listeners"
          ;;
        PORT-004)
          title="Docker listeners could not be inventoried"
          description="The socket listing could not be read to inventory Docker listeners"
          ;;
        PORT-005)
          title="Multicast listeners could not be inventoried"
          description="The socket listing could not be read to inventory multicast listeners"
          ;;
        PORT-006)
          title="Globally exposed listeners could not be audited"
          description="The socket listing could not be read to audit globally exposed listeners"
          ;;
      esac

      finding \
        id="$id" \
        category=ports \
        severity=info \
        title="$title" \
        description="$description" \
        expected="Socket listing available for auditing" \
        actual="ss exited with status $status" \
        recommendation="Verify ss availability and network visibility"
    done

    return 0
  fi

  finding \
    id=PORT-001 \
    category=ports \
    severity=info \
    title="Local listeners detected" \
    description="Services are listening only on loopback interfaces" \
    expected="Local-only listeners where remote access is not required" \
    actual="${#PORTS_LOCAL[@]} listeners" \
    recommendation="Review whether each local listener is expected"

  finding \
    id=PORT-002 \
    category=ports \
    severity=info \
    title="LAN listeners detected" \
    description="Services are listening on private network ranges" \
    expected="LAN listeners limited to networks that require access" \
    actual="${#PORTS_LAN[@]} listeners" \
    recommendation="Review whether each LAN listener is expected"

  finding \
    id=PORT-003 \
    category=ports \
    severity=info \
    title="VPN listeners detected" \
    description="Services are listening on VPN-related addresses" \
    expected="VPN listeners limited to services that require remote access" \
    actual="${#PORTS_VPN[@]} listeners" \
    recommendation="Review whether each VPN listener is expected"

  finding \
    id=PORT-004 \
    category=ports \
    severity=info \
    title="Docker listeners detected" \
    description="Services are listening on container-related interfaces or addresses" \
    expected="Container listeners isolated from untrusted networks" \
    actual="${#PORTS_DOCKER[@]} listeners" \
    recommendation="Review whether each container listener is expected"

  finding \
    id=PORT-005 \
    category=ports \
    severity=info \
    title="Multicast listeners detected" \
    description="Services are listening on multicast addresses" \
    expected="Multicast listeners limited to services that require discovery" \
    actual="${#PORTS_MULTICAST[@]} listeners" \
    recommendation="Review whether each multicast listener is expected"

  if ((${#PORTS_EXPOSED[@]} == 0)); then
    finding \
      id=PORT-006 \
      category=ports \
      severity=pass \
      title="No globally exposed listeners detected" \
      description="No listeners were bound to globally reachable addresses" \
      expected="No unnecessary globally exposed listeners" \
      actual="0 listeners" \
      recommendation="No action required"
  else
    summary=""
    limit=0

    for item in "${PORTS_EXPOSED[@]}"; do
      limit=$((limit + 1))

      if ((limit > 20)); then
        summary+="... truncated"
        break
      fi

      summary+="$item; "
    done

    finding \
      id=PORT-006 \
      category=ports \
      severity=medium \
      title="Globally exposed listeners detected" \
      description="One or more services are bound to globally reachable addresses" \
      expected="Only intentionally exposed services should listen globally" \
      actual="$summary" \
      recommendation="Review each exposed listener and confirm it is required and protected by firewall policy"
  fi
}

list_exposed_tcp_ports() {
  local status=0
  local summary
  local item
  local limit

  collect_listening_sockets || status=$?

  if ((status != 0)); then
    finding \
      id=PORT-007 \
      category=ports \
      severity=info \
      title="Globally exposed TCP listeners could not be audited" \
      description="The socket listing could not be read to audit globally exposed TCP listeners" \
      expected="Socket listing available for auditing" \
      actual="ss exited with status $status" \
      recommendation="Verify ss availability and network visibility"

    return 0
  fi

  if ((${#PORTS_EXPOSED_TCP[@]} == 0)); then
    finding \
      id=PORT-007 \
      category=ports \
      severity=pass \
      title="No globally exposed TCP listeners detected" \
      description="No TCP services were bound to globally reachable addresses" \
      expected="No unnecessary globally exposed TCP listeners" \
      actual="0 listeners" \
      recommendation="No action required"
  else
    summary=""
    limit=0

    for item in "${PORTS_EXPOSED_TCP[@]}"; do
      limit=$((limit + 1))

      if ((limit > 20)); then
        summary+="... truncated"
        break
      fi

      summary+="$item; "
    done

    finding \
      id=PORT-007 \
      category=ports \
      severity=high \
      title="Globally exposed TCP listeners detected" \
      description="One or more TCP services are bound to globally reachable addresses, increasing network exposure" \
      expected="Only intentionally exposed TCP services should listen globally" \
      actual="$summary" \
      recommendation="Confirm each exposed TCP service is required, patched, and restricted by firewall policy"
  fi
}
