# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security-sensitive reports.

Open a private GitHub security advisory instead:

https://github.com/Xwiuu/linux-security-auditor/security/advisories/new

Include steps to reproduce, the affected component, and the impact.

## Scope

In scope:

- LSA code (`lsa`, `lib/`, `modules/`, `parsers/`, `reporters/`, `tui/`)
- Installer and uninstaller (`install.sh`, `uninstall.sh`)
- Parsers handling authentication logs

Out of scope:

- Findings about the audited host itself (LSA is an auditor, not a remediation tool)
- Issues in third-party tools invoked by LSA (dnf, ss, firewall-cmd, ...)

## Supported versions

Security fixes are applied to the latest release and to `main`.
