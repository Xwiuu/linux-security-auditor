#!/usr/bin/env bash

check_pending_updates() {
  local output
  local status=0

  output="$(dnf check-update --quiet 2>&1)" || status=$?

  case "$status" in
    0)
      finding \
        id=UPDATE-001 \
        category=updates \
        severity=pass \
        title="No pending package updates" \
        description="The package manager reports no pending package updates" \
        expected="dnf check-update reports no outstanding updates" \
        actual="dnf check-update exited with status 0" \
        recommendation="No action required"
      ;;
    100)
      finding \
        id=UPDATE-001 \
        category=updates \
        severity=info \
        title="Pending package updates detected" \
        description="The package manager reports package updates that have not been applied" \
        expected="dnf check-update reports no outstanding updates" \
        actual="dnf check-update exited with status 100" \
        recommendation="Review and apply pending package updates"
      ;;
    *)
      finding \
        id=UPDATE-001 \
        category=updates \
        severity=info \
        title="Package update status could not be audited" \
        description="The pending package update check did not complete" \
        expected="dnf check-update reports no outstanding updates" \
        actual="dnf check-update exited with status $status" \
        recommendation="Verify dnf availability and repository access"
      ;;
  esac
}

check_security_updates() {
  local output
  local status=0
  local count

  output="$(LC_ALL=C dnf updateinfo list --security --updates 2>&1)" || status=$?

  if ((status != 0)); then
    finding \
      id=UPDATE-002 \
      category=updates \
      severity=info \
      title="Security update status could not be audited" \
      description="The pending security update check did not complete" \
      expected="dnf updateinfo reports no outstanding security updates" \
      actual="dnf updateinfo exited with status $status" \
      recommendation="Verify dnf availability and repository access"

    return 0
  fi

  count="$(
    awk '
        NR == 1 && $1 == "Name" { next }
        /^[[:alnum:]_.+-]+[[:space:]]+/ {
          count++
        }
        END {
          print count + 0
        }
      ' <<<"$output"
  )"

  if ((count == 0)); then
    finding \
      id=UPDATE-002 \
      category=updates \
      severity=pass \
      title="No pending security updates detected" \
      description="The package manager reports no pending security updates" \
      expected="dnf updateinfo reports no outstanding security updates" \
      actual="0 security updates listed" \
      recommendation="No action required"
  else
    finding \
      id=UPDATE-002 \
      category=updates \
      severity=medium \
      title="Pending security updates detected" \
      description="Security updates are available but have not been applied" \
      expected="dnf updateinfo reports no outstanding security updates" \
      actual="$count security updates listed" \
      recommendation="Apply the pending security updates"
  fi
}
