#!/usr/bin/env bash

# RFC 8259 Section 7 requires escaping quotation mark, reverse solidus,
# and control characters U+0000 through U+001F.
# Note: Bash variables cannot hold NUL bytes (0x00), which terminate C strings in Bash.
json_escape() {
  local value="$1"

  # Escape backslash and quotation mark first
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"

  # Standard two-character escape sequences
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  value="${value//$'\b'/\\b}"
  value="${value//$'\f'/\\f}"

  # Control characters U+0001 through U+001F in hex representation
  value="${value//$'\x01'/\\u0001}"
  value="${value//$'\x02'/\\u0002}"
  value="${value//$'\x03'/\\u0003}"
  value="${value//$'\x04'/\\u0004}"
  value="${value//$'\x05'/\\u0005}"
  value="${value//$'\x06'/\\u0006}"
  value="${value//$'\x07'/\\u0007}"
  value="${value//$'\x0b'/\\u000b}"
  value="${value//$'\x0e'/\\u000e}"
  value="${value//$'\x0f'/\\u000f}"
  value="${value//$'\x10'/\\u0010}"
  value="${value//$'\x11'/\\u0011}"
  value="${value//$'\x12'/\\u0012}"
  value="${value//$'\x13'/\\u0013}"
  value="${value//$'\x14'/\\u0014}"
  value="${value//$'\x15'/\\u0015}"
  value="${value//$'\x16'/\\u0016}"
  value="${value//$'\x17'/\\u0017}"
  value="${value//$'\x18'/\\u0018}"
  value="${value//$'\x19'/\\u0019}"
  value="${value//$'\x1a'/\\u001a}"
  value="${value//$'\x1b'/\\u001b}"
  value="${value//$'\x1c'/\\u001c}"
  value="${value//$'\x1d'/\\u001d}"
  value="${value//$'\x1e'/\\u001e}"
  value="${value//$'\x1f'/\\u001f}"

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

  for ((i = 0; i < total; i++)); do
    render_json_finding "$i"

    if ((i < total - 1)); then
      printf ','
    fi
  done

  printf ']}\n'
}

write_json_report() {
  local output_file="$1"

  render_json_findings >"$output_file"
}
