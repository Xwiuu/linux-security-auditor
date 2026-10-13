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

BIN_DIR="$PREFIX/bin"
LIB_DIR="$PREFIX/lib/linux-security-auditor"

if [[ ! -f "$ROOT_DIR/lsa" ]]; then
  printf '%s\n' 'Error: lsa entrypoint not found' >&2
  exit 1
fi

if ! mkdir -p "$BIN_DIR" "$LIB_DIR"; then
  printf 'Error: could not create directories under %s\n' "$PREFIX" >&2
  exit 1
fi

cp "$ROOT_DIR/lsa" "$LIB_DIR/lsa"

cp -r "$ROOT_DIR/lib" "$LIB_DIR/"
cp -r "$ROOT_DIR/modules" "$LIB_DIR/"
cp -r "$ROOT_DIR/parsers" "$LIB_DIR/"
cp -r "$ROOT_DIR/reporters" "$LIB_DIR/"
cp -r "$ROOT_DIR/tui" "$LIB_DIR/"

ln -sfn "$LIB_DIR/lsa" "$BIN_DIR/lsa"
chmod +x "$LIB_DIR/lsa"

if ! installed_version="$("$BIN_DIR/lsa" --version 2>/dev/null)"; then
  printf '%s\n' 'Error: installed executable failed smoke check' >&2
  exit 1
fi

printf 'Installed %s to %s\n' "$installed_version" "$LIB_DIR"
printf 'Executable: %s\n' "$BIN_DIR/lsa"

case ":$PATH:" in
  *":$BIN_DIR:"*)
    ;;
  *)
    printf '\n%s\n' "Note: $BIN_DIR is not currently in PATH."
    ;;
esac
