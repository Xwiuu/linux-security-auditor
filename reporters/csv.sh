#!/usr/bin/env bash

csv_escape() {
  local value="$1"

  value="${value//\"/\"\"}"

  printf '"%s"' "$value"
}


render_csv_findings() {
  local total
  local i

  total="$(findings_count)"

  printf '%s\n' \
    'id,category,severity,title,description,expected,actual,recommendation'

  for (( i = 0; i < total; i++ )); do
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$(csv_escape "$(findings_get "$i" id)")" \
      "$(csv_escape "$(findings_get "$i" category)")" \
      "$(csv_escape "$(finding_severity_tag "$(findings_get "$i" severity)")")" \
      "$(csv_escape "$(findings_get "$i" title)")" \
      "$(csv_escape "$(findings_get "$i" description)")" \
      "$(csv_escape "$(findings_get "$i" expected)")" \
      "$(csv_escape "$(findings_get "$i" actual)")" \
      "$(csv_escape "$(findings_get "$i" recommendation)")"
  done
}


write_csv_report() {
  local output_file="$1"

  render_csv_findings > "$output_file"
}
