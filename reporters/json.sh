#!/usr/bin/env bash

json_escape() {
  local value="$1"

  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"

  printf '%s' "$value"
}


render_json_finding() {
  local index="$1"

  printf '{'
  printf '"id":"%s",' \
    "$(json_escape "$(findings_get "$index" id)")"
  printf '"category":"%s",' \
    "$(json_escape "$(findings_get "$index" category)")"
  printf '"severity":"%s",' \
    "$(json_escape "$(finding_severity_tag "$(findings_get "$index" severity)")")"
  printf '"title":"%s",' \
    "$(json_escape "$(findings_get "$index" title)")"
  printf '"description":"%s",' \
    "$(json_escape "$(findings_get "$index" description)")"
  printf '"expected":"%s",' \
    "$(json_escape "$(findings_get "$index" expected)")"
  printf '"actual":"%s",' \
    "$(json_escape "$(findings_get "$index" actual)")"
  printf '"recommendation":"%s"' \
    "$(json_escape "$(findings_get "$index" recommendation)")"
  printf '}'
}


render_json_findings() {
  local total
  local i

  total="$(findings_count)"

  printf '{"findings":['

  for (( i = 0; i < total; i++ )); do
    render_json_finding "$i"

    if (( i < total - 1 )); then
      printf ','
    fi
  done

  printf ']}\n'
}


write_json_report() {
  local output_file="$1"

  render_json_findings > "$output_file"
}
