#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

INSTALLER="$ROOT_DIR/install.sh"
UNINSTALLER="$ROOT_DIR/uninstall.sh"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

prefix="$tmp_dir/prefix"

# Instalação básica
"$INSTALLER" --prefix "$prefix" >"$tmp_dir/install.out"

[[ -x "$prefix/bin/lsa" ]] ||
  fail "installed lsa is not executable"

[[ -L "$prefix/bin/lsa" ]] ||
  fail "installed lsa entrypoint is not a symlink"

[[ -f "$prefix/lib/linux-security-auditor/lsa" ]] ||
  fail "installed application entrypoint is missing"

version="$("$prefix/bin/lsa" --version)"

[[ "$version" == "Linux Security Auditor 0.1.0" ]] ||
  fail "unexpected installed version: $version"

# O bug da 24A: instalado não pode depender do cwd do repositório
(
  cd /tmp
  "$prefix/bin/lsa" --version >/dev/null
) || fail "installed lsa depends on repository working directory"

# Estrutura instalada
for dir in lib modules parsers reporters tui; do
  [[ -d "$prefix/lib/linux-security-auditor/$dir" ]] ||
    fail "missing installed directory: $dir"
done

[[ ! -e "$prefix/lib/linux-security-auditor/tests" ]] ||
  fail "tests should not be installed"

[[ ! -e "$prefix/lib/linux-security-auditor/.github" ]] ||
  fail "GitHub metadata should not be installed"

# Audit instalado
"$prefix/bin/lsa" audit --format json >"$tmp_dir/audit.json"

python3 -m json.tool "$tmp_dir/audit.json" >/dev/null ||
  fail "installed audit produced invalid JSON"

python3 - "$tmp_dir/audit.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)

if len(data["findings"]) != 40:
    raise SystemExit(
        f"expected 40 installed audit findings, got {len(data['findings'])}"
    )
PY

# Reinstalação
"$INSTALLER" --prefix "$prefix" >/dev/null ||
  fail "reinstallation failed"

"$prefix/bin/lsa" --version >/dev/null ||
  fail "installation broken after reinstall"

# Argumentos inválidos
if "$INSTALLER" --prefix >/dev/null 2>&1; then
  fail "installer accepted missing prefix value"
fi

if "$INSTALLER" --prefix relative/path >/dev/null 2>&1; then
  fail "installer accepted relative prefix"
fi

if "$INSTALLER" --banana >/dev/null 2>&1; then
  fail "installer accepted unknown option"
fi

if "$UNINSTALLER" --prefix relative/path >/dev/null 2>&1; then
  fail "uninstaller accepted relative prefix"
fi

if "$UNINSTALLER" --banana >/dev/null 2>&1; then
  fail "uninstaller accepted unknown option"
fi

# Uninstall
"$UNINSTALLER" --prefix "$prefix" >"$tmp_dir/uninstall.out"

[[ ! -e "$prefix/bin/lsa" ]] ||
  fail "lsa symlink still exists after uninstall"

[[ ! -e "$prefix/lib/linux-security-auditor" ]] ||
  fail "application directory still exists after uninstall"

# O desinstalador não pode apagar o prefixo inteiro
mkdir -p "$prefix/share"
touch "$prefix/share/keep-me"

"$INSTALLER" --prefix "$prefix" >/dev/null
"$UNINSTALLER" --prefix "$prefix" >/dev/null

[[ -f "$prefix/share/keep-me" ]] ||
  fail "uninstaller removed unrelated prefix content"

printf '%s\n' 'installer tests passed'
