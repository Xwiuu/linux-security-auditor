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
          printf "[WARN] AUTH-001 High number of SSH authentication failures from %s: %d\n",
                 ip, failures[ip]
          found = 1
        }
      }

      if (found == 0) {
        print "[PASS] AUTH-001 No suspicious SSH authentication failure volume detected"
      }
    }
  '
}
