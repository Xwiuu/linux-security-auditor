#!/usr/bin/env bash

LSA_DNF_TIMEOUT="${LSA_DNF_TIMEOUT:-15}"

_run_bounded_dnf() {
  local timeout_cmd=()
  if command -v timeout >/dev/null 2>&1; then
    timeout_cmd=(timeout "$LSA_DNF_TIMEOUT")
  fi

  "${timeout_cmd[@]}" dnf "$@" </dev/null
}

check_pending_updates() {
  local output
  local status=0

  output="$(_run_bounded_dnf check-update --assumeno --quiet 2>&1)" || status=$?

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
    124)
      finding \
        id=UPDATE-001 \
        category=updates \
        severity=info \
        title="Package update check timed out" \
        description="The pending package update check exceeded the timeout threshold (${LSA_DNF_TIMEOUT}s)" \
        expected="dnf check-update completes within ${LSA_DNF_TIMEOUT}s" \
        actual="dnf check-update timed out (status 124)" \
        recommendation="Verify repository responsiveness and network connectivity"
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

  output="$(LC_ALL=C _run_bounded_dnf updateinfo --assumeno list --security --updates 2>&1)" || status=$?

  if ((status != 0)); then
    local actual_msg="dnf updateinfo exited with status $status"
    local title_msg="Security update status could not be audited"
    local desc_msg="The pending security update check did not complete"

    if ((status == 124)); then
      title_msg="Security update check timed out"
      desc_msg="The pending security update check exceeded the timeout threshold (${LSA_DNF_TIMEOUT}s)"
      actual_msg="dnf updateinfo timed out (status 124)"
    fi

    finding \
      id=UPDATE-002 \
      category=updates \
      severity=info \
      title="$title_msg" \
      description="$desc_msg" \
      expected="dnf updateinfo reports no outstanding security updates" \
      actual="$actual_msg" \
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
