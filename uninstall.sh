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

while [[ "$PREFIX" != "/" && "$PREFIX" == */ ]]; do
  PREFIX="${PREFIX%/}"
done

BIN_DIR="$PREFIX/bin"
LIB_DIR="$PREFIX/lib/linux-security-auditor"
LSA_LINK="$BIN_DIR/lsa"
SEC_LINK="$BIN_DIR/sec-cli"
LSA_TARGET="$LIB_DIR/lsa"
SEC_TARGET="$LIB_DIR/sec-cli/bin/sec-cli"

is_managed_link() {
  local link="$1"
  local expected_target="$2"
  if [[ -L "$link" ]]; then
    local target
    target="$(readlink "$link" || true)"
    if [[ "$target" == "$expected_target" ]]; then
      return 0
    fi
  fi
  return 1
}

has_managed_install=0
if [[ -d "$LIB_DIR" ]]; then
  has_managed_install=1
fi
if is_managed_link "$LSA_LINK" "$LSA_TARGET"; then
  has_managed_install=1
fi
if is_managed_link "$SEC_LINK" "$SEC_TARGET"; then
  has_managed_install=1
fi

if ((has_managed_install == 0)); then
  printf 'Linux Security Auditor is not installed under %s\n' "$PREFIX"
  exit 0
fi

if is_managed_link "$LSA_LINK" "$LSA_TARGET"; then
  rm -f "$LSA_LINK"
  printf 'Removed executable: %s\n' "$LSA_LINK"
elif [[ -L "$LSA_LINK" ]]; then
  printf 'Note: %s is a symlink pointing elsewhere; leaving it untouched\n' "$LSA_LINK"
elif [[ -e "$LSA_LINK" ]]; then
  printf 'Note: %s exists but is not a symlink; leaving it untouched\n' "$LSA_LINK"
fi

if is_managed_link "$SEC_LINK" "$SEC_TARGET"; then
  rm -f "$SEC_LINK"
  printf 'Removed executable: %s\n' "$SEC_LINK"
elif [[ -L "$SEC_LINK" ]]; then
  printf 'Note: %s is a symlink pointing elsewhere; leaving it untouched\n' "$SEC_LINK"
elif [[ -e "$SEC_LINK" ]]; then
  printf 'Note: %s exists but is not a symlink; leaving it untouched\n' "$SEC_LINK"
fi

if [[ -d "$LIB_DIR" ]]; then
  rm -rf "$LIB_DIR"
  printf 'Removed: %s\n' "$LIB_DIR"
fi

printf 'Uninstalled Linux Security Auditor from %s\n' "$PREFIX"
