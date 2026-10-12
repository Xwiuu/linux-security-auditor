#!/usr/bin/env bash

list_listening_ports() {
  ss -tulpn
}

audit_listening_ports() {
  local line local_address iface addr_no_port

  while IFS= read -r line; do
    [[ "$line" == Netid* ]] && continue

    local_address="$(awk '{ print $5 }' <<<"$line")"
    addr_no_port="${local_address%:*}"
    iface=""
    [[ "$addr_no_port" == *%* ]] && iface="${addr_no_port#*%}"

    if [[ "$addr_no_port" == "127."* || "$addr_no_port" == "[::1]" || "$addr_no_port" == "::ffff:127."* ]]; then
      printf '[LOCAL] %s\n' "$line"
    elif [[ "$addr_no_port" == "224."* || "$addr_no_port" == "ff"* || "$addr_no_port" == "[ff"* ]]; then
      printf '[MULTICAST] %s\n' "$line"
    elif [[ "$iface" == docker* || "$iface" == br-* || "$iface" == virbr* || "$iface" == veth* ]] || [[ "$addr_no_port" =~ ^172\.(1[6-9]|2[0-9]|3[01])\.0\.1$ ]]; then
      printf '[DOCKER] %s\n' "$line"
    elif [[ "$addr_no_port" =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]] || [[ "$addr_no_port" == "[fd7a:115c:a1e0::"* ]] || [[ "$iface" == tailscale* || "$iface" == zt* ]]; then
      printf '[VPN] %s\n' "$line"
    elif [[ "$addr_no_port" == "192.168."* || "$addr_no_port" == "10."* || "$addr_no_port" == "172.1"[6-9].* || "$addr_no_port" == "172.2"[0-9].* || "$addr_no_port" == "172.3"[0-1].* || "$addr_no_port" == "[fd"* ]]; then
      printf '[LAN] %s\n' "$line"
    elif [[ "$addr_no_port" == "0.0.0.0" || "$addr_no_port" == "::" || "$addr_no_port" == "[::]" || "$addr_no_port" == "*" ]]; then
      printf '[EXPOSED] %s\n' "$line"
    else
      printf '[EXPOSED] %s\n' "$line"
    fi
  done < <(ss -tulpn)
}

summarize_listening_ports() {
  local output

  output="$(audit_listening_ports)"

  printf '[INFO] PORT-001 Local listeners: %s\n' \
    "$(grep -c '^\[LOCAL\]' <<<"$output" || true)"

  printf '[INFO] PORT-002 LAN listeners: %s\n' \
    "$(grep -c '^\[LAN\]' <<<"$output" || true)"

  printf '[INFO] PORT-003 VPN listeners: %s\n' \
    "$(grep -c '^\[VPN\]' <<<"$output" || true)"

  printf '[INFO] PORT-004 Docker listeners: %s\n' \
    "$(grep -c '^\[DOCKER\]' <<<"$output" || true)"

  printf '[INFO] PORT-005 Multicast listeners: %s\n' \
    "$(grep -c '^\[MULTICAST\]' <<<"$output" || true)"

  printf '[INFO] PORT-006 Globally exposed listeners: %s\n' \
    "$(grep -c '^\[EXPOSED\]' <<<"$output" || true)"
}

list_exposed_tcp_ports() {
  local output

  output="$(audit_listening_ports)"

  printf '%s\n' '[INFO] PORT-007 Globally exposed TCP listeners:'

  grep '^\[EXPOSED\] tcp[[:space:]]*LISTEN' <<<"$output" ||
    printf '%s\n' 'none'
}
