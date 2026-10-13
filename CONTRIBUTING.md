# Contributing

Thanks for your interest in improving Linux Security Auditor.

## Ground rules

- Bash only. No runtime dependencies beyond standard GNU/Linux utilities.
- Preserve the read-only design. Checks must never modify the host: no configuration changes, no service control, no firewall edits, no user or password changes.
- New dependencies require clear justification in the pull request.
- All checks emit structured findings through the finding engine (`lib/findings.sh`). Do not add raw `printf '[TAG]'` output.

## Development

Run the full quality gate before opening a pull request:

```bash
./scripts/check.sh
```

The same gate runs in GitHub Actions and must pass.

## Pull requests

- Keep changes focused: one concern per pull request.
- Add or extend tests when changing check behavior (`tests/`).
- Follow the existing code style; formatting is enforced by `.editorconfig` and shfmt.
