# Linux Security Auditor

Linux Security Auditor (LSA) is a Bash-based CLI for auditing common Linux security settings without modifying the host system.

The project focuses on readable security checks, structured findings, terminal-based workflows, and portable text/JSON/CSV reports.

## Current capabilities

- Host information discovery
- User and group auditing
- Sudo configuration checks
- Critical file permission checks
- SSH security checks
- Listening ports and services
- Firewall inspection
- Privileged process auditing
- Pending package and security updates
- SSH authentication journal parsing
- Authentication event normalization and analytics
- Structured finding engine
- Text, JSON, and CSV reporters
- Interactive terminal interface (TUI)

## Requirements

- Linux
- Bash
- Standard GNU/Linux utilities
- ShellCheck 0.11.0
- shfmt 3.14.1

Some audits require elevated privileges to access protected files or effective service configuration. When access is unavailable, LSA reports the check as non-auditable instead of treating it as a successful result.

## Usage

Show help:

```bash
./lsa --help
```

Run the complete audit:

```bash
./lsa audit
```

Choose an output format:

```bash
./lsa audit --format text
./lsa audit --format json
./lsa audit --format csv
```

Write the report to a file:

```bash
./lsa audit --format json --output reports/audit.json
```

Start the interactive terminal interface:

```bash
./lsa tui
```

Individual audit modules are also available:

```bash
./lsa host
./lsa users
./lsa sudo
./lsa permissions
./lsa ssh
./lsa ports
./lsa firewall
./lsa processes
./lsa updates
./lsa journal
./lsa sshlog
```

## Quality gate

Run the complete local quality gate:

```bash
./scripts/check.sh
```

The gate runs:

- Bash syntax validation
- shfmt
- ShellCheck
- findings tests
- CLI tests
- TUI tests
- runtime hardening tests
- structured audits tests

The same gate runs in GitHub Actions.

## Project status

Current version: `0.1.0`

The project is under active development. The auditor is read-only by design and does not automatically modify or remediate the host system.
