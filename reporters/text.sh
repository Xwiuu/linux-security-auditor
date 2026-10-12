#!/usr/bin/env bash

render_text_findings() {
  local total
  local i

  total="$(findings_count)"

  if (( total == 0 )); then
    printf '%s\n' 'No findings.'
    return 0
  fi

  for (( i = 0; i < total; i++ )); do
    printf '[%s] %s\n' \
      "$(finding_severity_tag "$(findings_get "$i" severity)")" \
      "$(findings_get "$i" id)"

    printf '%s\n\n' "$(findings_get "$i" title)"

    printf 'Description:\n%s\n\n' \
      "$(findings_get "$i" description)"

    printf 'Expected:\n%s\n\n' \
      "$(findings_get "$i" expected)"

    printf 'Actual:\n%s\n\n' \
      "$(findings_get "$i" actual)"

    printf 'Recommendation:\n%s\n' \
      "$(findings_get "$i" recommendation)"

    if (( i < total - 1 )); then
      printf '\n%s\n\n' '----------------------------------------'
    fi
  done

  printf '\n%s\n' '========================================'
  findings_summary
}


write_text_report() {
  local output_file="$1"

  render_text_findings > "$output_file"
}
