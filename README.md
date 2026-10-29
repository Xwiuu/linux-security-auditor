# Linux Security Auditor

Linux Security Auditor (LSA) is a read-only security auditing and diagnostics distribution for Linux systems.

The distribution provides two complementary, standalone command-line tools:
- **`lsa`**: Read-only Bash security auditor inspecting 40 host security configuration areas with CLI, TUI, and multi-format reporting.
- **`sec-cli`**: Perl Security Engineering CLI providing point-in-time network diagnostics, cryptographic file hashing, structured event logging, file integrity baselines, and `/proc` host telemetry.

`lsa` and `sec-cli` are distributed together and installed into the same prefix, but operate as independent commands.

---

## Highlights

- **40 Structured Audit Findings (`lsa`)**: User privileges, sudo rules, critical file permissions, SSH daemon configuration, exposed listening ports, firewall filtering, root processes, pending security updates, and systemd/auth journal events.
- **Security Engineering Diagnostics (`sec-cli`)**: DNS resolution, TCP reachability, SHA-256 file hashing, structured JSON logging, file integrity monitoring, and host resource telemetry.
- **Strictly Read-Only Design**: Neither tool modifies system files, alters permissions, touches firewall rules, enables services, or remediates findings.
- **Unified Output Formats**: Text, JSON, and CSV for `lsa`; structured JSON envelopes and human-readable text for `sec-cli`.
- **Interactive Terminal Interface**: Menu-driven TUI (`lsa tui`) for interactive audits and reporting.
- **Zero External Dependencies**: Core Bash and standard Perl core modules only; no CPAN packages, no Cargo/Rust, and no external daemons required.
- **Safe Packaging & Lifecycle**: Managed installer and idempotent uninstaller supporting custom installation prefixes without touching third-party files.

---

## Requirements

### Runtime Requirements
- Linux operating system (kernel with `/proc` filesystem support recommended for telemetry)
- Bash 4.0 or higher
- Perl 5.10 or higher (standard core modules: `Cwd`, `Digest::SHA`, `File::Basename`, `File::Spec`, `Getopt::Long`, `IO::Socket::IP`, `JSON::PP`, `Time::HiRes`)
- Standard GNU/Linux userland utilities (`coreutils`, `iproute2`, `grep`, `sed`, `awk`)

Some checks in `lsa` require elevated privileges (e.g. `/etc/shadow`, root crontabs). When read access is denied, LSA marks the check as non-auditable rather than reporting a false positive or treating it as passed.

### Development Requirements
- `ShellCheck` 0.11.0+
- `shfmt` 3.14.0+
- `prove` / `Test::More` (standard Perl test harness)

---

## Installation

Install both `lsa` and `sec-cli` using the provided installer:

```bash
git clone https://github.com/Xwiuu/linux-security-auditor.git
cd linux-security-auditor
./install.sh --prefix "$HOME/.local"
```

The installer verifies prerequisites, installs application libraries into `$PREFIX/lib/linux-security-auditor`, and creates managed symlinks in `$PREFIX/bin`:
- `$PREFIX/bin/lsa`
- `$PREFIX/bin/sec-cli`

Ensure `$PREFIX/bin` (e.g. `$HOME/.local/bin`) is included in your `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

The installer refuses to overwrite existing binaries or symlinks that point outside the managed LSA directory. Repeated installation is safe and idempotent.

---

## Usage: Bash Security Auditor (`lsa`)

### Full Audit Execution

```bash
# Terminal human-readable text report
lsa audit

# Explicit formats
lsa audit --format text
lsa audit --format json
lsa audit --format csv

# Save structured report to a file
lsa audit --format json --output reports/audit.json
```

### Individual Audit Modules

Run specific checks individually:

```bash
lsa host         # Hostname, OS release, kernel, architecture
lsa users        # Passwords, root UID, duplicate IDs, dormant accounts
lsa sudo         # NOPASSWD, wheel/sudo group membership
lsa permissions  # Critical paths (/etc/passwd, shadow, sudoers, SUID/SGID)
lsa ssh          # SSH daemon protocol, PermitRootLogin, PasswordAuthentication
lsa ports        # Listening TCP/UDP network services
lsa firewall     # iptables, nftables, ufw, firewalld inspection
lsa processes    # Non-root processes, privileged daemons
lsa updates      # DNF / APT pending security updates
lsa journal      # Systemd journal anomalies
lsa sshlog       # Authentication logs (/var/log/secure, /var/log/auth.log)
```

### Interactive Terminal Interface (TUI)

```bash
lsa tui
```

```text
Linux Security Auditor
======================

[1] Run full audit
[2] View findings
[3] Export report
[4] System information
[Q] Quit

Select an option:
```

---

## Usage: Security Engineering CLI (`sec-cli`)

`sec-cli` provides operational diagnostics and security verification subcommands. Output is formatted as structured JSON by default, or as text with `--format text`.

### 1. DNS Resolution (`dns`)
Resolves forward IPv4 (`A`) and IPv6 (`AAAA`) addresses for a given hostname with timing:

```bash
sec-cli dns localhost
sec-cli dns google.com --format text --timeout 2
```

### 2. TCP Connectivity (`tcp-check`)
Checks TCP connectivity and handshake latency against a target host and port:

```bash
sec-cli tcp-check 127.0.0.1 22 --timeout 3
sec-cli tcp-check 192.168.1.1 443 --format text
```

### 3. File Hashing (`hash`)
Computes cryptographic SHA-256 digests and validates file stability during read:

```bash
sec-cli hash /etc/passwd
sec-cli hash /bin/bash --format text
```

### 4. Structured Event Logging (`log`)
Emits standardized JSON log events with ISO 8601 timestamps and optional structured context:

```bash
sec-cli log "Auditing started" --level info
sec-cli log "Unauthorized change detected" --level warn --context '{"target":"/etc/ssh"}'
```

### 5. Integrity Baseline Initialization (`integrity-init`)
Generates an inventory baseline file containing SHA-256 digests, permissions, ownership, and symlink targets for a directory tree:

```bash
sec-cli integrity-init /etc --output /var/tmp/etc-baseline.json
sec-cli integrity-init /etc --output /var/tmp/etc-baseline.json --force
```

### 6. Integrity Verification (`integrity-verify`)
Compares current filesystem state against a previously generated baseline and reports unchanged, modified, added, removed, or error items:

```bash
sec-cli integrity-verify /etc --baseline /var/tmp/etc-baseline.json
sec-cli integrity-verify /etc --baseline /var/tmp/etc-baseline.json --format text
```

### 7. Host Telemetry (`host-metrics`)
Collects host telemetry directly from `/proc` (`/proc/meminfo`, `/proc/loadavg`, `/proc/self/mountinfo`) with zero subprocess forks:

```bash
sec-cli host-metrics
sec-cli host-metrics --format text
```

Reports:
- Memory: Total, available, free, swap total, and swap free (in KiB).
- System load averages: 1-minute, 5-minute, and 15-minute averages.
- Mount points: Target path, filesystem type, and kernel security mount flags (`nodev`, `nosuid`, `noexec`).

---

## Exit Codes

### `lsa` Exit Codes
- `0`: Successful execution (findings may be present in report output).
- `1`: Invocation error, unknown option, or execution failure.

### `sec-cli` Exit Codes
- `0`: Successful operation / file integrity check passed with zero modifications.
- `1`: Warning condition (e.g. file modified concurrently during hashing, or integrity drift detected during verification).
- `2`: Invalid command-line arguments, unknown command, or syntax error.
- `3`: Operational error (I/O failure, permission denied, connection refused, or resolution timeout).

---

## Security Model & Limitations

- **Read-Only Scope**: The suite does not remediate findings, fix insecure permissions, alter firewall rules, or touch credentials.
- **Permission Boundaries**: If a file or configuration item cannot be read due to DAC or MAC restrictions, the check is explicitly recorded as non-auditable rather than passed.
- **Point-in-Time Verification**: `integrity-verify` performs on-demand comparisons against a stored snapshot. It is **not** a continuous file monitoring system, inotify daemon, or real-time intrusion prevention engine.
- **Durability Notice**: Baseline generation applies atomic file writes and directory synchronization (`fsync`), but filesystem-level crash durability guarantees depend on underlying filesystem semantics, mount flags, and storage hardware.
- **Telemetry Boundaries**: `host-metrics` reports kernel system load averages and memory figures. It does **not** measure CPU utilization percentages or process scheduling overhead.
- **Decoupled Architecture**: `lsa` and `sec-cli` are installed together but execute independently. `lsa audit` does not automatically invoke `sec-cli`.

---

## Uninstallation

To remove LSA from your system:

```bash
./uninstall.sh --prefix "$HOME/.local"
```

The uninstaller removes only managed links (`$PREFIX/bin/lsa`, `$PREFIX/bin/sec-cli`) and the application directory (`$PREFIX/lib/linux-security-auditor`). Unrelated files in `$PREFIX/bin` or `$PREFIX` remain untouched. Uninstallation is idempotent.

---

## Local Development & Quality Gates

Run the local quality gates before submitting changes:

```bash
# Run all Bash syntax checks, formatting checks, and test suites
./scripts/check.sh </dev/null

# Run Perl test harness (syntax, network, hashing, integrity, metrics)
prove -r sec-cli/t

# Check for trailing whitespace or formatting diffs
git diff --check
```

---

## Architecture

```text
linux-security-auditor/
├── lsa                      # Bash audit CLI entrypoint and orchestrator
├── lib/                     # Finding engine, logger, and utility functions
├── modules/                 # Bash audit modules (host, users, permissions, ssh, etc.)
├── parsers/                 # Authentication and systemd journal log parsers
├── reporters/               # Text, JSON, and CSV reporters
├── tui/                     # Interactive terminal user interface
├── sec-cli/
│   ├── bin/
│   │   └── sec-cli          # Perl Security Engineering CLI executable
│   ├── lib/LSA/SecEng/      # Perl modules (DNS, TCP, Hash, Logger, Integrity, HostMetrics)
│   └── t/                   # Perl unit and regression test suite
├── scripts/
│   └── check.sh             # Canonical Bash quality gate
├── tests/                   # Bash unit, TUI, CLI, hardening, and installer tests
├── install.sh               # Standalone installer
└── uninstall.sh             # Standalone uninstaller
```
