#!/usr/bin/env bash

is_valid_severity() {
  case "$1" in
    pass|info|low|medium|warn|high|critical)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

declare -ga LSA_FINDING_FIELDS=(
  id
  category
  severity
  title
  description
  expected
  actual
  recommendation
)

declare -ga LSA_FINDINGS=()


finding_reset() {
  LSA_FINDINGS=()
}


finding_severity_tag() {
  case "$1" in
    pass)     printf 'PASS' ;;
    info)     printf 'INFO' ;;
    low)      printf 'LOW' ;;
    medium)   printf 'MEDIUM' ;;
    warn)     printf 'WARN' ;;
    high)     printf 'HIGH' ;;
    critical) printf 'CRITICAL' ;;
    *)        printf 'UNKNOWN' ;;
  esac
}


finding_severity_rank() {
  case "$1" in
    critical) printf '6' ;;
    high)     printf '5' ;;
    warn)     printf '4' ;;
    medium)   printf '3' ;;
    low)      printf '2' ;;
    info)     printf '1' ;;
    pass)     printf '0' ;;
    *)        return 1 ;;
  esac
}


finding_field_offset() {
  case "$1" in
    id)             printf '0' ;;
    category)       printf '1' ;;
    severity)       printf '2' ;;
    title)          printf '3' ;;
    description)    printf '4' ;;
    expected)       printf '5' ;;
    actual)         printf '6' ;;
    recommendation) printf '7' ;;
    *)              return 1 ;;
  esac
}


finding() {
  local id="" category="" severity="info" title=""
  local description="" expected="" actual="" recommendation=""
  local arg

  for arg in "$@"; do
    case "$arg" in
      id=*)             id="${arg#id=}" ;;
      category=*)       category="${arg#category=}" ;;
      severity=*)       severity="${arg#severity=}" ;;
      title=*)          title="${arg#title=}" ;;
      description=*)    description="${arg#description=}" ;;
      expected=*)       expected="${arg#expected=}" ;;
      actual=*)         actual="${arg#actual=}" ;;
      recommendation=*) recommendation="${arg#recommendation=}" ;;
      *)
        printf 'Error: unknown finding field: %s\n' "$arg" >&2
        return 1
        ;;
    esac
  done

  if ! is_valid_severity "$severity"; then
    printf 'Error: invalid finding severity: %s\n' "$severity" >&2
    return 1
  fi

  if [[ -z "$id" ]]; then
    printf 'Error: finding requires id=\n' >&2
    return 1
  fi

  if [[ -z "$title" ]]; then
    printf 'Error: finding %s requires title=\n' "$id" >&2
    return 1
  fi

  LSA_FINDINGS+=(
    "$id"
    "$category"
    "$severity"
    "$title"
    "$description"
    "$expected"
    "$actual"
    "$recommendation"
  )
}


findings_count() {
  printf '%s\n' "$(( ${#LSA_FINDINGS[@]} / ${#LSA_FINDING_FIELDS[@]} ))"
}


findings_get() {
  local index="$1"
  local name="$2"
  local offset
  local slot

  if ! offset="$(finding_field_offset "$name")"; then
    printf 'Error: unknown finding field: %s\n' "$name" >&2
    return 1
  fi

  if ! [[ "$index" =~ ^[0-9]+$ ]]; then
    printf 'Error: finding index must be a number: %s\n' "$index" >&2
    return 1
  fi

  slot=$(( index * ${#LSA_FINDING_FIELDS[@]} + offset ))
  printf '%s\n' "${LSA_FINDINGS[$slot]:-}"
}


findings_summary() {
  local total
  local i
  local severity
  local pass=0
  local info=0
  local low=0
  local medium=0
  local warn=0
  local high=0
  local critical=0

  total="$(findings_count)"

  for (( i = 0; i < total; i++ )); do
    severity="$(findings_get "$i" severity)"

    case "$severity" in
      pass)     pass=$(( pass + 1 )) ;;
      info)     info=$(( info + 1 )) ;;
      low)      low=$(( low + 1 )) ;;
      medium)   medium=$(( medium + 1 )) ;;
      warn)     warn=$(( warn + 1 )) ;;
      high)     high=$(( high + 1 )) ;;
      critical) critical=$(( critical + 1 )) ;;
    esac
  done

  printf 'Findings: %s total (%s pass, %s info, %s low, %s medium, %s warn, %s high, %s critical)\n' \
    "$total" \
    "$pass" \
    "$info" \
    "$low" \
    "$medium" \
    "$warn" \
    "$high" \
    "$critical"
}
