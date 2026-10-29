#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PREFIX="${HOME}/.local"

show_help() {
  cat <<'EOF'
Linux Security Auditor installer

Usage:
  ./install.sh [--prefix PATH]

Options:
  --prefix PATH   Installation prefix (default: $HOME/.local)
  -h, --help      Show this help
EOF
}

while (($# > 0)); do
  case "$1" in
    --prefix)
      if (($# < 2)); then
        printf '%s\n' 'Error: --prefix requires a path' >&2
        exit 1
      fi

      PREFIX="$2"
      shift 2
      ;;

    -h | --help)
      show_help
      exit 0
      ;;

    *)
      printf 'Error: unknown option: %s\n' "$1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$PREFIX" ]]; then
  printf '%s\n' 'Error: --prefix requires a non-empty path' >&2
  exit 1
fi

if [[ "$PREFIX" != /* ]]; then
  printf '%s\n' 'Error: --prefix must be an absolute path' >&2
  exit 1
fi

while [[ "$PREFIX" != "/" && "$PREFIX" == */ ]]; do
  PREFIX="${PREFIX%/}"
done

BIN_DIR="$PREFIX/bin"
LIB_DIR="$PREFIX/lib/linux-security-auditor"
LSA_LINK="$BIN_DIR/lsa"
SEC_LINK="$BIN_DIR/sec-cli"
LSA_TARGET="$LIB_DIR/lsa"
SEC_TARGET="$LIB_DIR/sec-cli/bin/sec-cli"

if [[ ! -f "$ROOT_DIR/lsa" ]]; then
  printf '%s\n' 'Error: lsa entrypoint not found' >&2
  exit 1
fi

if [[ ! -f "$ROOT_DIR/sec-cli/bin/sec-cli" || ! -d "$ROOT_DIR/sec-cli/lib/LSA" ]]; then
  printf '%s\n' 'Error: sec-cli components not found' >&2
  exit 1
fi

if ! command -v perl >/dev/null 2>&1; then
  printf '%s\n' 'Error: perl runtime is required' >&2
  exit 1
fi

# Verify existing binary paths do not belong to unrelated software
if [[ -L "$LSA_LINK" ]]; then
  existing_lsa_target="$(readlink "$LSA_LINK" || true)"
  if [[ "$existing_lsa_target" != "$LSA_TARGET" ]]; then
    printf 'Error: %s already exists and does not point to %s\n' "$LSA_LINK" "$LSA_TARGET" >&2
    exit 1
  fi
elif [[ -e "$LSA_LINK" ]]; then
  printf 'Error: %s already exists and is not a managed symlink\n' "$LSA_LINK" >&2
  exit 1
fi

if [[ -L "$SEC_LINK" ]]; then
  existing_sec_target="$(readlink "$SEC_LINK" || true)"
  if [[ "$existing_sec_target" != "$SEC_TARGET" ]]; then
    printf 'Error: %s already exists and does not point to %s\n' "$SEC_LINK" "$SEC_TARGET" >&2
    exit 1
  fi
elif [[ -e "$SEC_LINK" ]]; then
  printf 'Error: %s already exists and is not a managed symlink\n' "$SEC_LINK" >&2
  exit 1
fi

if ! mkdir -p "$BIN_DIR" "$LIB_DIR/sec-cli/bin" "$LIB_DIR/sec-cli/lib"; then
  printf 'Error: could not create directories under %s\n' "$PREFIX" >&2
  exit 1
fi

cp "$ROOT_DIR/lsa" "$LIB_DIR/lsa"

cp -r "$ROOT_DIR/lib" "$LIB_DIR/"
cp -r "$ROOT_DIR/modules" "$LIB_DIR/"
cp -r "$ROOT_DIR/parsers" "$LIB_DIR/"
cp -r "$ROOT_DIR/reporters" "$LIB_DIR/"
cp -r "$ROOT_DIR/tui" "$LIB_DIR/"

cp "$ROOT_DIR/sec-cli/bin/sec-cli" "$LIB_DIR/sec-cli/bin/sec-cli"
cp -r "$ROOT_DIR/sec-cli/lib/LSA" "$LIB_DIR/sec-cli/lib/"

chmod +x "$LIB_DIR/lsa"
chmod +x "$LIB_DIR/sec-cli/bin/sec-cli"

ln -sfn "$LSA_TARGET" "$LSA_LINK"
ln -sfn "$SEC_TARGET" "$SEC_LINK"

if ! installed_lsa_version="$("$LSA_LINK" --version 2>/dev/null)"; then
  printf '%s\n' 'Error: installed executable failed smoke check' >&2
  exit 1
fi

if ! installed_sec_version="$("$SEC_LINK" --version 2>/dev/null)"; then
  printf '%s\n' 'Error: installed sec-cli executable failed smoke check' >&2
  exit 1
fi

printf 'Installed %s to %s\n' "$installed_lsa_version" "$LIB_DIR"
printf 'Installed %s to %s\n' "$installed_sec_version" "$LIB_DIR"
printf 'Executable: %s\n' "$LSA_LINK"
printf 'Executable: %s\n' "$SEC_LINK"

case ":$PATH:" in
  *":$BIN_DIR:"*)
    ;;
  *)
    printf '\n%s\n' "Note: $BIN_DIR is not currently in PATH."
    ;;
esac
