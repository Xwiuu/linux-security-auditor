# Sprint 01 Implementation Plan: Security Engineering CLI (Perl)

**Component:** `sec-cli` (Security Engineering CLI)  
**Implementation Language:** Modern Perl (5.32+)  
**Dependency Policy:** Pure Standard Library (Zero CPAN dependencies)  
**Status:** Ready for CTO Review & Approval  
**Estimated Effort:** 1 Sprint (2 weeks)  

---

## 1. Technical Justification & Strategic Context

The repository audit confirmed that while GNU Bash excels at shell-level configuration inspection and file permission checks, it exhibits key deficiencies in:
1. **Network Diagnostics:** Bash lacks native TCP/UDP socket handling without relying on external binaries (`nc`, `curl`, `telnet`) or unstable `/dev/tcp` pseudo-devices.
2. **Cryptographic Primitives:** Bash has no built-in hashing; relying on `sha256sum` incurs process fork overhead.
3. **Structured Network Timeouts:** Implementing non-blocking sub-second timeouts in pure Bash is brittle.

Perl provides robust POSIX network sockets, streaming cryptographic digests (`Digest::SHA`), high-resolution timers (`Time::HiRes`), and JSON serialization (`JSON::PP`) directly in its standard core library.

*Availability Note:* While Perl is standard on enterprise and cloud distributions (RHEL, Rocky, Alma, Debian, Ubuntu), its availability varies across minimal, containerized, or appliance Linux installations (such as Alpine or distroless images). `sec-cli` is designed as a standalone tool for environments where Perl is present.

---

## 2. Sprint 01 Scope & Command Suite

Sprint 01 focuses **exclusively** on the standalone executable `./sec-cli/bin/sec-cli` with four core commands. *(File integrity baselining and Bash module fixes are deferred to subsequent sprints/tasks).*

### 2.1. `sec-cli hash <file> [--algo sha256] [--format json|text]`
- Computes SHA-256 for a target file using core `Digest::SHA`.
- Reads files in 64 KB streaming chunks (low memory footprint for large binaries).
- Returns file path, hash, byte size, file mode, and last modified epoch timestamp.
- Fails safely if the file is unreadable or a broken symlink.

### 2.2. `sec-cli tcp-check <host> <port> [--timeout <seconds>] [--format json|text]`
- Tests TCP connectivity to `<host>:<port>` using `IO::Socket::IP` with non-blocking connection semantics.
- **Timeout Policy:** Default timeout is 3.0 seconds; maximum configurable timeout is 10.0 seconds.
- Measures precise round-trip connection latency in milliseconds using `Time::HiRes`.
- Validates hostnames/IP addresses against strict regex (disallowing shell meta-characters).
- Detects refused connections, host unreachable, and timeouts distinctly.
- Returns exit code `124` only when a timeout condition has been positively established.

### 2.3. `sec-cli dns <hostname> [--timeout <seconds>] [--format json|text]`
- Resolves forward IPv4/IPv6 addresses for a given hostname using `Socket::getaddrinfo`.
- **DNS Timeout Correctness & Limitations:**
  - Standard C library / Perl resolver calls (`getaddrinfo`) block synchronously within operating system libc routines.
  - In certain thread, libc, or network stack conditions, signal-based interrupts (`alarm`) may be delayed or deferred until kernel network calls complete.
  - Therefore, application-requested timeouts for DNS must be treated as **implementation-dependent and best-effort**. No guaranteed hard deadline can be promised without specialized asynchronous resolver architectures or helper processes.
  - Per strict YAGNI, external dependencies or asynchronous resolver daemons will **not** be introduced without a demonstrated functional requirement.
- Sanitizes hostname inputs against length (RFC 1035: <= 253 characters) and valid character sets (`[a-zA-Z0-9.-]`).

### 2.4. `sec-cli log <message> [--level info|warn|error] [--context JSON]`
- Outputs structured JSON log lines compliant with cloud-native log ingestion pipelines.
- Automatically injects UTC timestamp, hostname, PID, and severity level.

### 2.5. Scope Boundaries & Deferred Features
- **File integrity baselining (`integrity-init`) and verification (`integrity-verify`) are deferred to Sprint 02.**
- **Existing Bash module fixes (`updates.sh`, `host.sh`, `permissions.sh`, `json.sh`) are tracked under a separate future hardening task.**
- **No Docker integration is included in this sprint.**

---

## 3. Directory Layout & Module Structure

```
sec-cli/
├── bin/
│   └── sec-cli                 # Executable entrypoint (strict, warnings, Getopt::Long)
├── lib/
│   └── LSA/
│       └── SecEng/
│           ├── DNS.pm          # DNS resolution via Socket / getaddrinfo
│           ├── TCP.pm          # TCP connectivity via IO::Socket::IP & non-blocking select
│           ├── Hash.pm         # Digest::SHA chunked streaming
│           └── Logger.pm       # Structured JSON log formatter
└── t/
    ├── 00_syntax.t             # Compilation and syntax check (perl -c)
    ├── 01_hash.t               # Hashing assertions against known vectors
    ├── 02_tcp.t                # Localhost TCP connectivity & timeout handling
    ├── 03_dns.t                # Synthetic, syntax, and error DNS resolutions
    └── 04_cli_options.t        # Command line flags and exit code verification
```

---

## 4. Strict Technical Constraints

1. **Pure Perl Core Only:**
   The implementation strictly uses modules included in the standard Perl core distribution:
   - `strict`, `warnings`
   - `Getopt::Long`
   - `Socket` and `IO::Socket::IP`
   - `Digest::SHA`
   - `JSON::PP`
   - `File::Spec`, `File::Basename`
   - `Time::HiRes`
   - `POSIX`
   - `Test::More` (test harness only)
   *Zero CPAN external dependencies.*

2. **No Shell Invocations:**
   The Perl code must never invoke `/bin/sh` or execute external commands via backticks or `system("string")`. All socket, hashing, and file inspections are performed via native Perl APIs.

3. **Safe File Handling:**
   - Always open files with explicit 3-argument `open`: `open my $fh, '<:raw', $path`.

4. **Predictable Exit Codes:**
   - `0`: Success (clean execution).
   - `1`: Warning / Finding (target port closed).
   - `2`: CLI usage / syntax error.
   - `3`: Environmental error (file unreadable, network unreachable).
   - `124`: Execution Timeout (only when timeout condition is positively established).

---

## 5. Verification & Testing Strategy

A dedicated test suite in `sec-cli/t/` will validate functionality locally without relying on external network or public DNS availability:

1. **Cryptographic Validation (`01_hash.t`):**
   - Assert SHA-256 calculations against known NIST test vectors and temporary test files.
   - Verify 0-byte file handling.
2. **Network Resilience (`02_tcp.t`):**
   - Test connectivity to an ephemeral local listener.
   - Test connection refusal against an unbound local port.
   - Assert timeout behavior against a non-routable test address (RFC 5737 `192.0.2.1` TEST-NET-1).
3. **DNS Validation (`03_dns.t`):**
   - Assert resolution of local synthetic hostnames (`localhost`, `127.0.0.1`).
   - Assert invalid hostname syntax rejection without network queries.
   - Assert non-existent domain error handling without public DNS dependencies.
4. **Automated Runner:**
   - Execute tests using standard Perl test harness: `prove -r sec-cli/t`.

---

## 6. Definition of Done (Sprint 01 Acceptance Criteria)

- [ ] Executable `./sec-cli/bin/sec-cli` operates standalone.
- [ ] Commands `hash`, `tcp-check`, `dns`, and `log` fully implemented and functional.
- [ ] All machine outputs strictly conform to `schemas/sec-ops.v1.json`.
- [ ] Zero CPAN / external runtime dependencies.
- [ ] 100% of tests in `sec-cli/t/` pass via `prove -r sec-cli/t` in an environment with Perl.
- [ ] Existing `./scripts/check.sh` remains completely untouched and passing.
- [ ] No host modifications performed outside of user-specified output files.
