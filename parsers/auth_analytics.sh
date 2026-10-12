#!/usr/bin/env bash

count_auth_failures() {
  awk -F'|' '$2 == "AUTH_FAILURE" { count++ } END { print count + 0 }'
}

count_auth_failures_by_ip() {
  awk -F'|' '
    $2 == "AUTH_FAILURE" {
      failures[$4]++
    }

    END {
      for (ip in failures) {
        print ip "|" failures[ip]
      }
    }
  '
}

detect_suspicious_ips() {
  local threshold="${1:-5}"

  awk -F'|' -v threshold="$threshold" '
    $2 == "AUTH_FAILURE" {
      failures[$4]++
    }

    END {
      found = 0

      for (ip in failures) {
        if (failures[ip] >= threshold) {
          printf "%s|%d\n", ip, failures[ip]
          found = 1
        }
      }

      if (found == 0) {
        print "NONE|0"
      }
    }
  '
}

build_auth_findings() {
  local result
  local ip
  local count

  result="$(detect_suspicious_ips "${1:-5}")"

  while IFS='|' read -r ip count; do
    if [[ "$ip" == "NONE" ]]; then
      finding \
        id=AUTH-001 \
        category=authentication \
        severity=pass \
        title="No suspicious SSH authentication failure volume detected" \
        description="No source IP reached the configured failed authentication threshold" \
        expected="Fewer than ${1:-5} failed attempts per source IP" \
        actual="No source IP reached the threshold" \
        recommendation="Continue monitoring authentication activity"

      continue
    fi

    finding \
      id=AUTH-001 \
      category=authentication \
      severity=medium \
      title="High SSH authentication failure volume" \
      description="Multiple failed SSH authentication attempts were detected from the same source IP" \
      expected="Fewer than ${1:-5} failed attempts per source IP" \
      actual="${count} failed attempts from ${ip}" \
      recommendation="Review the source IP and related SSH authentication logs"
  done <<< "$result"
}
