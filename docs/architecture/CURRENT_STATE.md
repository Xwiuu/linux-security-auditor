# Architecture Audit & Baseline: Current State (v1.0.0)

**Date:** October 2026  
**Auditor:** Senior Security Engineer / Software Architect  
**Reviewer:** CTO (ChatGPT)  
**Repository:** `https://github.com/Xwiuu/linux-security-auditor`  
**Base Commit SHA:** `3f51a24329f10ddb5a1b71017284ef6db5676414`  
**Release Tag:** `v1.0.0`  
**License:** MIT  

---

## 1. Executive Summary

Linux Security Auditor (LSA) v1.0.0 is an open-source, read-only system auditing utility implemented in GNU Bash (Bash 4+). It relies on bash-specific features—such as indexed arrays, regex matching, parameter substitutions, and `[[ ]]` test operators—and is distinct from standard POSIX `sh`. Its objective is auditing security-sensitive Linux host configurations and generating structured findings across Text, JSON, and CSV formats, in addition to an interactive Terminal User Interface (TUI).

The repository demonstrates disciplined shell scripting practices:
- Enforced strict shell runtime settings (`set -Eeuo pipefail`) across all executables and test suites.
- Static quality gates passing ShellCheck (`v0.11.0`) and `shfmt` (`v3.14.1`) with zero linting warnings.
- Modular separation into CLI orchestrator, core finding engine, audit modules, log parsers, reporters, and TUI.
- Read-only execution model during audit runs.

Historical evidence from GitHub Actions run `38393876438` confirms a successful quality gate at the base commit `3f51a24329f10ddb5a1b71017284ef6db5676414`. Local quality gate execution (`./scripts/check.sh </dev/null`) independently confirmed that all 9 validation stages pass.

---

## 2. Repository Inventory & Directory Structure

```
linux-security-auditor/
├── CHANGELOG.md                # Semantic versioning release log (v1.0.0)
├── CONTRIBUTING.md             # Contribution policy and coding standards
├── install.sh                  # Host-level local prefix installer
├── lib/
│   ├── core.sh                 # Banner and fatal exit helper (`die`)
│   ├── findings.sh             # Flat-array finding engine (8 fields per finding)
│   ├── logger.sh               # Terminal logging helpers ([INFO], [WARN], [ERROR])
│   └── utils.sh                # Command existence predicate (`command_exists`)
├── LICENSE                     # MIT License
├── lsa                         # Main CLI entrypoint and orchestrator
├── modules/
│   ├── firewall.sh             # Firewall backend detection and firewalld inspection
│   ├── host.sh                 # System identification and uptime
│   ├── permissions.sh          # Critical system and user file permission auditing
│   ├── ports.sh                # Listening socket classification and exposed TCP analysis
│   ├── processes.sh            # Root process counting, executable paths and permissions
│   ├── ssh.sh                  # OpenSSH server daemon hardening checks
│   ├── sudo.sh                 # Sudoers syntax, file permissions, NOPASSWD & wildcard rules
│   ├── updates.sh              # Pending package and security update checks (DNF)
│   └── users.sh                # UID 0, interactive shells, admin groups, empty passwords
├── parsers/
│   ├── auth_analytics.sh       # Aggregation of authentication failures and IP metrics
│   ├── journal.sh              # Systemd journal extraction for sshd units
│   ├── normalize.sh            # Pipe-delimited event normalizer from raw SSH logs
│   └── ssh_auth.sh             # SSH authentication event filter
├── README.md                   # Project documentation and usage guide
├── reporters/
│   ├── csv.sh                  # CSV report formatter with column escaping
│   ├── json.sh                 # JSON report serializer
│   └── text.sh                 # Human-readable plain text finding formatter
├── scripts/
│   ├── check.sh                # Canonical quality gate script (static lint + test suites)
├── SECURITY.md                 # Vulnerability disclosure policy and scope
├── tests/
│   ├── cli_test.sh             # CLI flags, report formats, exit codes
│   ├── findings_test.sh        # Unit tests for the finding engine
│   ├── installer_test.sh       # Isolated installation/uninstallation integration tests
│   ├── runtime_hardening_test.sh # Mocked execution resilience tests
│   ├── structured_audits_test.sh # Comprehensive mocked audit assertions (40 findings)
│   └── tui_test.sh             # TUI header and smoke verification
├── tui/
│   └── main.sh                 # Interactive ncurses-like ANSI menu interface
└── uninstall.sh                # Clean uninstaller matching install.sh
```

---

## 3. Architecture Topology & Execution Model

```
                    ┌───────────────────────────────┐
                    │       User Invocation         │
                    │   (./lsa audit / tui / etc.)  │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │      Entrypoint Orchestrator  │
                    │            (./lsa)            │
                    └───────────────┬───────────────┘
                                    │
             ┌──────────────────────┴──────────────────────┐
             │                                             │
             ▼                                             ▼
┌─────────────────────────┐                   ┌─────────────────────────┐
│     Audit Modules       │                   │       TUI Engine        │
│      (modules/*.sh)     │                   │       (tui/main.sh)     │
└────────────┬────────────┘                   └────────────┬────────────┘
             │                                             │
             │   Emits finding id=... category=...         │
             ▼                                             │
┌─────────────────────────────────────────┐                │
│             Finding Engine              │◄───────────────┘
│            (lib/findings.sh)            │
│   - In-memory array: LSA_FINDINGS       │
│   - 8-slot stride per finding record    │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│            Reporters Engine             │
│   ├── reporters/text.sh                 │
│   ├── reporters/json.sh                 │
│   └── reporters/csv.sh                  │
└────────────────────┬────────────────────┘
                     │
                     ▼
          Standard Output or File
```

### 3.1. Finding Engine (`lib/findings.sh`)
The core finding engine manages findings in a global flat Bash indexed array (`LSA_FINDINGS`).
- **Stride:** 8 positional fields per finding:
  1. `id`: Unique identifier (e.g., `USER-001`, `SSH-003`, `FW-001`).
  2. `category`: Audit domain (`users`, `sudo`, `permissions`, `ssh`, `ports`, `firewall`, `processes`, `updates`).
  3. `severity`: Validation tag (`pass`, `info`, `low`, `medium`, `warn`, `high`, `critical`).
  4. `title`: Short descriptive title.
  5. `description`: Background context on what is evaluated.
  6. `expected`: Secure baseline state.
  7. `actual`: Discovered state on audited host.
  8. `recommendation`: Concrete remediation guidance.
- **Finding Inventory:** A full audit run consistently registers exactly **40 structured findings**:
  - `users`: 5 findings (`USER-001` .. `USER-005`)
  - `sudo`: 5 findings (`SUDO-001` .. `SUDO-005`)
  - `permissions`: 7 findings (`PERM-001` .. `PERM-007`)
  - `ssh`: 7 findings (`SSH-001` .. `SSH-007`)
  - `updates`: 2 findings (`UPDATE-001`, `UPDATE-002`)
  - `processes`: 3 findings (`PROC-001` .. `PROC-003`)
  - `ports`: 7 findings (`PORT-001` .. `PORT-007`)
  - `firewall`: 4 findings (`FW-001` .. `FW-004`)

---

## 4. Quality Gate & Baseline Verification

The canonical quality gate is defined in `./scripts/check.sh` and mirrored in `.github/workflows/quality.yml`.

### 4.1. Local Quality Gate Execution
- Environment: Linux x86_64, GNU bash 5.3.9, ShellCheck 0.11.0, shfmt 3.14.1, Python 3.14.8.
- Execution Command: `./scripts/check.sh </dev/null`

| Step | Check Name | Command | Result | Notes |
|---|---|---|---|---|
| 1 | Bash Syntax | `bash -n lsa lib/*.sh modules/*.sh ...` | **PASS** | Clean syntax |
| 2 | Code Formatting | `shfmt -d lsa lib/*.sh ...` | **PASS** | 100% formatted to style |
| 3 | ShellCheck | `shellcheck -x lsa lib/*.sh ...` | **PASS** | 0 warnings across codebase |
| 4 | Findings Tests | `bash tests/findings_test.sh` | **PASS** | 36 unit assertions passed |
| 5 | TUI Tests | `bash tests/tui_test.sh` | **PASS** | Header and smoke tests passed |
| 6 | Hardening Tests | `bash tests/runtime_hardening_test.sh` | **PASS** | Mocked binary tests passed |
| 7 | Structured Tests | `bash tests/structured_audits_test.sh` | **PASS** | 40 mock finding assertions verified |
| 8 | CLI Tests | `bash tests/cli_test.sh </dev/null` | **PASS** | Verified default, text, json, csv |
| 9 | Installer Tests | `bash tests/installer_test.sh </dev/null` | **PASS** | Verified isolated prefix install/uninstall |

**Overall Result: ALL CHECKS PASSED.**  
*(GitHub Actions historical run `38393876438` at base commit confirms CI parity).*

---

## 5. Confirmed Architectural Limitations

The following limitations were independently verified by inspecting the codebase:

1. **`journal` and `sshlog` do not currently use the same structured reporting path as the 40 audit checks:**
   - In `lsa` (lines 285-290), `journal` invokes `read_auth_journal` and `sshlog` invokes `parse_ssh_auth_events`.
   - In `parsers/journal.sh` and `parsers/ssh_auth.sh`, output is printed as raw unstructured text or formatted strings (`printf '[INFO] JOURNAL-001...'`).
   - Neither parser calls `finding()` in `lib/findings.sh`, meaning their outputs do not appear in `findings.v1.json`, CSV reports, or the 40 structured findings count.
2. **Firewall inspection relies primarily on `firewall-cmd`:**
   - In `modules/firewall.sh`, `detect_firewall_backend()` detects `firewalld`, `nftables`, `iptables`, and `ufw`.
   - However, `collect_firewall_state()` explicitly checks:
     ```bash
     if ! command -v firewall-cmd >/dev/null 2>&1; then
       return 0
     fi
     ```
   - Consequently, all detailed rule checks (`check_active_zones`, `check_active_zone_rules`, `check_broad_port_ranges`) only function on systems where `firewall-cmd` is active. Systems running native `nftables`, `iptables`, or `ufw` are treated as non-auditable.
3. **Existing JSON reports do not expose an explicit schema version:**
   - In `reporters/json.sh` (`render_json_findings()`), the JSON root is:
     ```json
     {"findings":[ ... ]}
     ```
   - It omits `schema_version`, `$schema`, or metadata indicating report generation time, target host, or contract version.
4. **The installer depends on existing repository paths:**
   - In `install.sh`, the script resolves `ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"` and explicitly copies directories relative to the source clone:
     ```bash
     cp "$ROOT_DIR/lsa" "$LIB_DIR/lsa"
     cp -r "$ROOT_DIR/lib" "$LIB_DIR/"
     cp -r "$ROOT_DIR/modules" "$LIB_DIR/"
     cp -r "$ROOT_DIR/parsers" "$LIB_DIR/"
     cp -r "$ROOT_DIR/reporters" "$LIB_DIR/"
     cp -r "$ROOT_DIR/tui" "$LIB_DIR/"
     ```
   - It cannot install from standalone files or separate distribution tarballs without the exact repository directory hierarchy present on disk.
5. **Manual JSON escaping requires additional testing before accepting arbitrary external input:**
   - In `reporters/json.sh`, `json_escape()` performs manual string substitution:
     ```bash
     value="${value//\\/\\\\}"
     value="${value//\"/\\\"}"
     value="${value//$'\n'/\\n}"
     value="${value//$'\r'/\\r}"
     value="${value//$'\t'/\\t}"
     ```
   - While sufficient for the 40 built-in static audit strings, it does not escape ASCII control characters (U+0000 through U+001F, except `\n`, `\r`, `\t`), which violates RFC 8259 if host-provided inputs (process names, process arguments, or network banners) contain non-printable control characters.

---

## 6. Discrepancies Between README Claims and Source Code

1. **Silent Individual Module Execution:**
   - README (lines 57-69) advertises individual module invocations: `lsa users`, `lsa sudo`, `lsa permissions`, `lsa processes`, `lsa updates`.
   - In `lsa` (lines 232-284), invoking these subcommands populates the internal `LSA_FINDINGS` array but never invokes a reporter (`render_text_findings`). They exit silently with code 0 and empty stdout.
2. **Hardcoded Package Manager Assumption:**
   - `modules/updates.sh` directly invokes `dnf check-update` and `dnf updateinfo`. On Debian, Ubuntu, or Alpine systems, update audits report non-auditable `info` findings.
3. **Subprocess Interactive Blocking:**
   - In `modules/updates.sh`, `dnf check-update --quiet 2>&1` without closed stdin (`</dev/null`) or timeout causes `lsa audit` to halt waiting for interactive confirmation when untrusted repository keys require user input.

*(Remediation of existing Bash module issues is tracked as a separate future hardening task outside of Sprint 01).*
