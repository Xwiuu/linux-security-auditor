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

# Scenario 1: Fresh installation with custom prefix
"$INSTALLER" --prefix "$prefix" >"$tmp_dir/install.out"

# Scenario 2: Installed lsa --version works
[[ -x "$prefix/bin/lsa" ]] ||
  fail "installed lsa is not executable"

[[ -L "$prefix/bin/lsa" ]] ||
  fail "installed lsa entrypoint is not a symlink"

[[ -f "$prefix/lib/linux-security-auditor/lsa" ]] ||
  fail "installed application entrypoint is missing"

lsa_version="$("$prefix/bin/lsa" --version)"

[[ "$lsa_version" == "Linux Security Auditor 1.0.0" ]] ||
  fail "unexpected installed lsa version: $lsa_version"

# Scenario 3: Installed lsa --help works
"$prefix/bin/lsa" --help >"$tmp_dir/lsa_help.out"
grep -q "Linux Security Auditor" "$tmp_dir/lsa_help.out" ||
  fail "installed lsa --help missing expected content"

# Scenario 4: Installed sec-cli --version works
[[ -x "$prefix/bin/sec-cli" ]] ||
  fail "installed sec-cli is not executable"

[[ -L "$prefix/bin/sec-cli" ]] ||
  fail "installed sec-cli entrypoint is not a symlink"

[[ -f "$prefix/lib/linux-security-auditor/sec-cli/bin/sec-cli" ]] ||
  fail "installed sec-cli binary is missing"

sec_version="$("$prefix/bin/sec-cli" --version)"
[[ "$sec_version" =~ ^sec-cli\ version\ 1\.0\.0 ]] ||
  fail "unexpected installed sec-cli version: $sec_version"

# Scenario 5: Installed sec-cli --help lists all seven commands
"$prefix/bin/sec-cli" --help >"$tmp_dir/sec_help.out"
for cmd in dns tcp-check hash log integrity-init integrity-verify host-metrics; do
  grep -q "$cmd" "$tmp_dir/sec_help.out" ||
    fail "installed sec-cli --help missing command: $cmd"
done

# Verified installed commands work without relying on repository working directory
(
  cd /tmp
  "$prefix/bin/lsa" --version >/dev/null
  "$prefix/bin/sec-cli" --version >/dev/null
) || fail "installed executables depend on repository working directory"

# Directory structure checks
for dir in lib modules parsers reporters tui sec-cli/bin sec-cli/lib; do
  [[ -d "$prefix/lib/linux-security-auditor/$dir" ]] ||
    fail "missing installed directory: $dir"
done

[[ ! -e "$prefix/lib/linux-security-auditor/tests" ]] ||
  fail "tests should not be installed"

[[ ! -e "$prefix/lib/linux-security-auditor/sec-cli/t" ]] ||
  fail "sec-cli tests should not be installed"

[[ ! -e "$prefix/lib/linux-security-auditor/.github" ]] ||
  fail "GitHub metadata should not be installed"

# Scenario 6: Installed sec-cli hash works on a temporary regular file
test_hash_file="$tmp_dir/sample_hash.txt"
printf 'sample content for hash\n' >"$test_hash_file"
(
  cd /tmp
  "$prefix/bin/sec-cli" hash "$test_hash_file" --format json >"$tmp_dir/hash.json"
) || fail "installed sec-cli hash failed outside repository"

python3 - "$tmp_dir/hash.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)

if data.get("status") != "success" or data.get("exit_code") != 0:
    raise SystemExit(f"hash command failed: {data}")
if not data.get("data", {}).get("hash"):
    raise SystemExit("hash value missing in output")
PY

# Scenario 7: Installed sec-cli integrity-init creates a baseline
integrity_target="$tmp_dir/integrity_target"
baseline_out="$tmp_dir/baseline.json"
mkdir -p "$integrity_target/subdir"
printf 'file A content\n' >"$integrity_target/file_a.txt"
printf 'file B content\n' >"$integrity_target/subdir/file_b.txt"

(
  cd /tmp
  "$prefix/bin/sec-cli" integrity-init "$integrity_target" --output "$baseline_out" --format json >"$tmp_dir/init.json"
) || fail "installed sec-cli integrity-init failed"

[[ -f "$baseline_out" ]] || fail "baseline output file was not created"

# Scenario 8: Installed sec-cli integrity-verify validates an unchanged directory
(
  cd /tmp
  "$prefix/bin/sec-cli" integrity-verify "$integrity_target" --baseline "$baseline_out" --format json >"$tmp_dir/verify.json"
) || fail "installed sec-cli integrity-verify failed on unchanged directory"

python3 - "$tmp_dir/verify.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)

if data.get("status") != "success" or data.get("exit_code") != 0:
    raise SystemExit(f"integrity-verify failed: {data}")
summary = data.get("data", {}).get("summary", {})
if summary.get("unchanged") != 2 or summary.get("modified") != 0 or summary.get("added") != 0 or summary.get("removed") != 0:
    raise SystemExit(f"unexpected integrity summary: {summary}")
PY

# Scenario 9: Installed sec-cli host-metrics works on supported Linux hosts or is conditionally skipped
if [[ -r /proc/meminfo && -r /proc/loadavg && -r /proc/self/mountinfo ]]; then
  (
    cd /tmp
    "$prefix/bin/sec-cli" host-metrics --format json >"$tmp_dir/metrics.json"
  ) || fail "installed sec-cli host-metrics failed"

  python3 - "$tmp_dir/metrics.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)

if data.get("status") != "success" or data.get("exit_code") != 0:
    raise SystemExit(f"host-metrics failed: {data}")
if "memory" not in data.get("data", {}) or "load_average" not in data.get("data", {}):
    raise SystemExit(f"missing expected metric sections: {data.get('data')}")
PY
fi

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

# Scenario 10: Repeated installation is safe
"$INSTALLER" --prefix "$prefix" >/dev/null ||
  fail "reinstallation failed"

"$prefix/bin/lsa" --version >/dev/null ||
  fail "lsa broken after reinstall"

"$prefix/bin/sec-cli" --version >/dev/null ||
  fail "sec-cli broken after reinstall"

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

# Missing perl detection
no_perl_bin="$tmp_dir/no_perl_bin"
mkdir -p "$no_perl_bin"
# Copy minimal utilities needed for bash scripts without perl
for tool in dirname basename mkdir cp chmod ln rm readlink printf; do
  tool_path="$(command -v "$tool" || true)"
  if [[ -n "$tool_path" && -x "$tool_path" ]]; then
    ln -s "$tool_path" "$no_perl_bin/$tool"
  fi
done
if (PATH="$no_perl_bin" "$INSTALLER" --prefix "$tmp_dir/no_perl_prefix" >/dev/null 2>&1); then
  fail "installer succeeded when perl runtime is missing"
fi

# Scenario 14: Installation refuses to overwrite an unrelated sec-cli executable or link
conflict_prefix="$tmp_dir/conflict_prefix"
mkdir -p "$conflict_prefix/bin"
touch "$conflict_prefix/bin/sec-cli"
chmod +x "$conflict_prefix/bin/sec-cli"

if "$INSTALLER" --prefix "$conflict_prefix" >/dev/null 2>&1; then
  fail "installer overwrote an unrelated regular file at bin/sec-cli"
fi

# Verify the unrelated file was untouched
[[ -f "$conflict_prefix/bin/sec-cli" && ! -L "$conflict_prefix/bin/sec-cli" ]] ||
  fail "unrelated bin/sec-cli was altered by failed install"

rm -f "$conflict_prefix/bin/sec-cli"
ln -s "/bin/echo" "$conflict_prefix/bin/sec-cli"

if "$INSTALLER" --prefix "$conflict_prefix" >/dev/null 2>&1; then
  fail "installer overwrote an unrelated symlink at bin/sec-cli"
fi

[[ "$(readlink "$conflict_prefix/bin/sec-cli")" == "/bin/echo" ]] ||
  fail "unrelated symlink bin/sec-cli was altered by failed install"

# Scenario 15: Partial installation and ownership-conflict behavior is tested
# Test conflict with unrelated lsa file
touch "$conflict_prefix/bin/lsa"
if "$INSTALLER" --prefix "$conflict_prefix" >/dev/null 2>&1; then
  fail "installer overwrote an unrelated regular file at bin/lsa"
fi
rm -f "$conflict_prefix/bin/lsa"

# Test uninstaller preserving unrelated symlink or file
"$UNINSTALLER" --prefix "$conflict_prefix" >/dev/null 2>&1 || true
[[ -L "$conflict_prefix/bin/sec-cli" && "$(readlink "$conflict_prefix/bin/sec-cli")" == "/bin/echo" ]] ||
  fail "uninstaller deleted unrelated symlink bin/sec-cli"

# Scenario 11: Uninstallation removes managed executables
# Scenario 12: Uninstallation preserves unrelated files
mkdir -p "$prefix/share"
touch "$prefix/share/keep-me"
touch "$prefix/bin/keep-other-tool"

"$UNINSTALLER" --prefix "$prefix" >"$tmp_dir/uninstall.out"

[[ ! -e "$prefix/bin/lsa" ]] ||
  fail "lsa symlink still exists after uninstall"

[[ ! -e "$prefix/bin/sec-cli" ]] ||
  fail "sec-cli symlink still exists after uninstall"

[[ ! -e "$prefix/lib/linux-security-auditor" ]] ||
  fail "application directory still exists after uninstall"

[[ -f "$prefix/share/keep-me" ]] ||
  fail "uninstaller removed unrelated share file"

[[ -f "$prefix/bin/keep-other-tool" ]] ||
  fail "uninstaller removed unrelated bin tool"

# Scenario 13: Repeated uninstallation is safe
"$UNINSTALLER" --prefix "$prefix" >"$tmp_dir/uninstall_repeat.out" ||
  fail "repeated uninstallation failed"

grep -q "not installed" "$tmp_dir/uninstall_repeat.out" ||
  fail "repeated uninstallation did not report clean state"

printf '%s\n' 'installer tests passed'
