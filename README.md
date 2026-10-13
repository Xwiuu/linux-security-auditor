# Linux Security Auditor

Linux Security Auditor (LSA) is a read-only Bash security auditing tool for Linux systems.

It inspects common security-sensitive configuration areas and produces structured findings without modifying the host.

## Highlights

- 40 structured audit findings
- User and privilege auditing
- Sudo configuration checks
- Critical file permissions
- SSH hardening checks
- Ports and service exposure
- Firewall analysis
- Root process inspection
- Package and security updates
- Authentication log parsing
- Text, JSON and CSV output
- Interactive terminal interface
- Installer/uninstaller
- Automated quality gate and CI

## Requirements

- Linux
- Bash
- Standard GNU/Linux utilities
- ShellCheck 0.11.0 (development only)
- shfmt 3.14.1 (development only)

Some audits require elevated privileges to access protected files or effective service configuration. When access is unavailable, LSA reports the check as non-auditable instead of treating it as a successful result.

## Installation

```bash
git clone https://github.com/Xwiuu/linux-security-auditor.git
cd linux-security-auditor
./install.sh --prefix "$HOME/.local"
```

Make sure `$HOME/.local/bin` is in your `PATH`. The installer prints a note when it is not.

## Usage

```bash
lsa --help
lsa audit
lsa audit --format text
lsa audit --format json
lsa audit --format csv
lsa audit --format json --output reports/audit.json
```

Individual audit modules:

```bash
lsa host
lsa users
lsa sudo
lsa permissions
lsa ssh
lsa ports
lsa firewall
lsa processes
lsa updates
lsa journal
lsa sshlog
```

## Terminal interface

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

## Uninstall

```bash
./uninstall.sh --prefix "$HOME/.local"
```

The uninstaller removes only what the installer created and leaves the rest of the prefix untouched.

## Security model

LSA is read-only by design.

It does not:

- modify configuration
- enable services
- change firewall rules
- alter users or passwords
- generate SSH host keys

When a protected resource cannot be inspected, the check is reported as non-auditable instead of successful.

## Architecture

```text
lsa                 entrypoint, CLI and audit orchestration
lib/                finding engine, logger, shared helpers
modules/            audit checks (users, sudo, ssh, ports, firewall, ...)
parsers/            authentication journal and event parsing
reporters/          text, JSON and CSV output
tui/                interactive terminal interface
scripts/check.sh    canonical quality gate
install.sh          installer
uninstall.sh        uninstaller
tests/              automated test suites
```

Every check emits structured findings through a single engine, and reporters render the same data as text, JSON or CSV.

## Quality gate

```bash
./scripts/check.sh
```

Runs:

- bash syntax validation
- shfmt
- ShellCheck
- findings tests
- CLI tests
- TUI tests
- runtime hardening tests
- structured audit tests
- installer tests

The same gate runs in GitHub Actions on every push and pull request.

## Project status

Current development version: `0.1.0`.

Preparing for v1.0. Planned after v1.0: migrating the remaining journal and sshlog checks to the structured finding engine, and packaging (RPM/DEB) if there is real demand.
