#!/usr/bin/env bash
set -Eeuo pipefail

PREFIX="${HOME}/.local"

show_help() {
  cat <<'EOF'
Linux Security Auditor uninstaller

Usage:
  ./uninstall.sh [--prefix PATH]

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
LINK="$BIN_DIR/lsa"

if [[ ! -d "$LIB_DIR" && ! -L "$LINK" ]]; then
  printf 'Linux Security Auditor is not installed under %s\n' "$PREFIX"
  exit 0
fi

if [[ -L "$LINK" ]]; then
  rm "$LINK"
  printf 'Removed executable: %s\n' "$LINK"
elif [[ -e "$LINK" ]]; then
  printf 'Note: %s exists but is not a symlink; leaving it untouched\n' "$LINK"
fi

if [[ -d "$LIB_DIR" ]]; then
  rm -rf "$LIB_DIR"
  printf 'Removed: %s\n' "$LIB_DIR"
fi

printf 'Uninstalled Linux Security Auditor from %s\n' "$PREFIX"
