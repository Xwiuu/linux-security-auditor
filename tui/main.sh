#!/usr/bin/env bash

tui_clear() {
  if [[ -t 1 ]]; then
    printf '\033[2J\033[H'
  fi
}

tui_header() {
  printf '%s\n' 'Linux Security Auditor'
  printf '%s\n\n' '======================'
}

tui_run_audit() {
  tui_clear
  tui_header

  printf '%s\n\n' 'Running security audit...'

  run_audit

  printf '%s\n' 'Audit complete.'
  findings_summary
}

tui_view_findings() {
  local count

  tui_clear
  tui_header

  count="$(findings_count)"

  if (( count == 0 )); then
    printf '%s\n' 'No findings loaded.'
    printf '%s\n' 'Run a full audit first.'
    return 0
  fi

  render_text_findings
}

tui_cleanup() {
  printf '\033[0m'
}

tui_export_report() {
  local format
  local output_file
  local output_dir

  tui_clear
  tui_header

  if (( $(findings_count) == 0 )); then
    printf '%s\n' 'No findings loaded.'
    printf '%s\n' 'Run a full audit first.'
    return 0
  fi

  printf '%s\n' '[1] Text'
  printf '%s\n' '[2] JSON'
  printf '%s\n' '[3] CSV'
  printf '%s\n' '[B] Back'
  printf '\nSelect format: '

  if ! IFS= read -r format; then
    return 0
  fi

  case "$format" in
    1)
      format="text"
      ;;
    2)
      format="json"
      ;;
    3)
      format="csv"
      ;;
    b|B)
      return 0
      ;;
    *)
      printf '%s\n' 'Invalid format.'
      return 0
      ;;
  esac

  printf 'Output file: '

  if ! IFS= read -r output_file; then
    return 0
  fi

  if [[ -z "$output_file" ]]; then
    printf '%s\n' 'Output file cannot be empty.'
    return 0
  fi

  output_dir="$(dirname "$output_file")"

  if [[ ! -d "$output_dir" ]]; then
    printf 'Output directory does not exist: %s\n' "$output_dir"
    return 0
  fi

  case "$format" in
    text)
      write_text_report "$output_file"
      ;;
    json)
      write_json_report "$output_file"
      ;;
    csv)
      write_csv_report "$output_file"
      ;;
  esac

  printf '\nReport exported to: %s\n' "$output_file"
}

tui_main_menu() {
  local choice

  trap tui_cleanup RETURN

  while true; do
    tui_clear
    tui_header

    printf '%s\n' '[1] Run full audit'
    printf '%s\n' '[2] View findings'
    printf '%s\n' '[3] Export report'
    printf '%s\n' '[4] System information'
    printf '%s\n\n' '[Q] Quit'

    printf 'Select an option: '

    if ! IFS= read -r choice; then
      return 0
    fi

    case "$choice" in
      1)
        tui_run_audit
        ;;
      2)
        tui_view_findings
        ;;
      3)
        tui_export_report
        ;;
      4)
        printf '%s\n' 'System information not wired yet.'
        ;;
      q|Q)
        return 0
        ;;
      *)
        printf '%s\n' 'Invalid option.'
        ;;
    esac

    printf '\nPress Enter to continue...'
    IFS= read -r || true
  done
}
