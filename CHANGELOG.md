# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Structured audit engine with 40 security findings
- CLI covering users, sudo, permissions, SSH, ports, firewall, processes, updates and host information
- Authentication journal parsing and event analytics
- Text, JSON and CSV reporters
- Interactive terminal interface (TUI)
- Installer and uninstaller (`install.sh`, `uninstall.sh`)
- Canonical quality gate (`scripts/check.sh`) with six test suites
- GitHub Actions CI running the same gate on every push and pull request
- README, LICENSE (MIT), CONTRIBUTING and SECURITY policies

### Security

- Read-only audit model: no host mutation of any kind
- Hardened error handling under `set -Eeuo pipefail`
- Non-auditable results reported explicitly instead of silent success
- Runtime hardening test suite covering dnf, journalctl, getent, firewall-cmd and missing sudoers/os-release scenarios
