#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

command -v shfmt >/dev/null 2>&1 ||
  {
    printf '%s\n' 'Error: shfmt is required' >&2
    exit 1
  }

command -v shellcheck >/dev/null 2>&1 ||
  {
    printf '%s\n' 'Error: shellcheck is required' >&2
    exit 1
  }

printf '%s\n' '==> bash syntax'
bash -n \
  lsa \
  lib/*.sh \
  modules/*.sh \
  parsers/*.sh \
  reporters/*.sh \
  tui/*.sh \
  tests/*.sh

printf '%s\n' '==> shfmt'
shfmt -d \
  lsa \
  lib/*.sh \
  modules/*.sh \
  parsers/*.sh \
  reporters/*.sh \
  tui/*.sh \
  tests/*.sh

printf '%s\n' '==> shellcheck'
shellcheck -x \
  lsa \
  lib/*.sh \
  modules/*.sh \
  parsers/*.sh \
  reporters/*.sh \
  tui/*.sh \
  tests/*.sh

printf '%s\n' '==> findings tests'
bash tests/findings_test.sh

printf '%s\n' '==> CLI tests'
bash tests/cli_test.sh

printf '%s\n' '==> TUI tests'
bash tests/tui_test.sh

printf '%s\n' '==> runtime hardening tests'
bash tests/runtime_hardening_test.sh

printf '%s\n' 'all checks passed'
