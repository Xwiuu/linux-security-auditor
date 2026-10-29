# Threat Model & Security Posture Analysis

**Status:** Initial Threat Model  
**Version:** 1.0.0  
**Phase:** Sprint 00 Analysis  
**Auditor:** Senior Security Engineer / Software Architect  
**Reviewer:** CTO (ChatGPT)  

---

## 1. Scope & Methodology

This threat model assesses the security posture of the **Linux Security Auditor (LSA)** ecosystem. It identifies threats, attack vectors, and necessary defensive controls using the STRIDE methodology:
- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

The analysis strictly differentiates between:
1. **Current State Risks (v1.0.0 Bash Baseline)**
2. **Future State Risks (Perl CLI, Tentative Platform Collectors, Backend & WASM UI)**

*Policy Note: Unverified theoretical risks are not classified as confirmed vulnerabilities.*

---

## 2. Current State Risks (v1.0.0 Bash Baseline)

*(Note: Remediation of existing Bash module issues is tracked as a separate future hardening task outside of Sprint 01).*

### 2.1. Local Command Execution & Sourcing
- **Threat:** Evaluation of untrusted shell syntax.
- **Implementation Detail:**
  - In `modules/host.sh` (lines 22 and 33):
    ```bash
    if [[ -r "$OS_RELEASE_FILE" ]]; then
      source "$OS_RELEASE_FILE"
    fi
    ```
  - If a local user or adversary modifies `/etc/os-release` (or if `$OS_RELEASE_FILE` is redirected via environment to an untrusted file), `source` interprets arbitrary shell commands with the privileges of the auditor.
- **Mitigation (Future Bash Hardening Task):**
  - Parse required keys (`NAME=`, `VERSION=`) line-by-line using `awk` or `grep` without shell sourcing.

### 2.2. Denial of Service via Interactive Subprocess Blocking
- **Threat:** Subprocess blocking on interactive input.
- **Implementation Detail:**
  - In `modules/updates.sh` (lines 7 & 51):
    `output="$(dnf check-update --quiet 2>&1)"`
  - On systems where unimported third-party repository keys exist, `dnf` halts on stdin waiting for interactive key confirmation (`Is this ok [y/N]:`).
  - Without standard input redirection (`</dev/null`) or non-interactive options (`-y` / `--assumeno`), `lsa audit` hangs indefinitely.
- **Mitigation (Future Bash Hardening Task):**
  - Enforce standard input closure (`</dev/null`) and explicit execution timeouts on subprocess calls.

### 2.3. Privilege Boundaries & Information Disclosure
- **Threat:** Overprivileged execution or blind spots during unprivileged runs.
- **Implementation Detail:**
  - Several checks require root permissions: reading `/etc/shadow`, running `visudo -c`, and querying `sshd -T` (which reads private host keys).
  - Standard user execution degrades gracefully to `info` ("could not be audited"), but running `lsa` as `root` increases blast radius.
- **Mitigation (Future Bash Hardening Task):**
  - Maintain the read-only audit invariant. Avoid running entire suites under full root; where necessary, rely on specific read permissions or granular capabilities (`CAP_DAC_READ_SEARCH`).

### 2.4. Untrusted File Paths & Symlink Dereferencing
- **Threat:** Symlink attacks / TOCTOU.
- **Implementation Detail:**
  - In `modules/permissions.sh`:
    `mode="$(stat -c '%a' "$file" 2>/dev/null || true)"`
  - `stat -c` dereferences symlinks by default. If a critical file is replaced with a symlink pointing to another location, `stat -c` evaluates the target file's permissions rather than detecting the symlink anomaly.
  - Pre-checking symlink status via shell tests (e.g. `[[ -L "$file" ]]`) does **not** eliminate Time-of-Check to Time-of-Use (TOCTOU) races between check and consumption.
- **Mitigation (Future Bash Hardening Task):**
  - Enforce atomic operating-system primitives (such as `O_NOFOLLOW` or `openat2(..., RESOLVE_NO_SYMLINKS)`) where syscall control is available, or use `lstat` semantics.

### 2.5. Manual JSON Escaping Limitations
- **Threat:** Malformed JSON output or parser errors when processing non-standard characters.
- **Implementation Detail:**
  - In `reporters/json.sh`, `json_escape()` manually replaces backslashes, double quotes, newlines, carriage returns, and tabs.
  - It does not escape raw ASCII control characters (U+0000 through U+001F, except `\n`, `\r`, `\t`). If untrusted host inputs (such as process command-line arguments or corrupted network service banners) contain control characters, the resulting JSON output violates RFC 8259.
- **Mitigation (Future Bash Hardening Task):**
  - Expand test suites to cover binary/control-character inputs and transition to native JSON encoders in subsequent language modules.

---

## 3. Future State Risks (Platform Evolution)

### 3.1. Security Engineering CLI in Perl (`sec-cli`, Sprint 01)
- **Threat: Shell Command Injection**
  - *Risk:* Passing unsanitized inputs to shell strings (`system("cmd $arg")`).
  - *Mitigation:* Strict prohibition of shell string execution. Always use list-based invocation (`system(@args)`) and native Perl core APIs (`Socket`, `Digest::SHA`).
- **Threat: Unbounded Network Scanning / SSRF**
  - *Risk:* `tcp-check` and `dns` abused to probe internal network segments or cloud metadata endpoints (`169.254.169.254`).
  - *Mitigation:* Input validation on hostnames/IPs, explicit timeout limits (TCP default 3s, max 10s), and default exclusion of link-local metadata addresses.
- **Threat: Unhandled Resolver Deadlines**
  - *Risk:* Expectation that DNS queries terminate on hard deadlines despite blocking system resolver calls.
  - *Mitigation:* Explicitly document that resolver timeouts are implementation-dependent; do not promise guaranteed deadlines without low-level asynchronous resolver support.

### 3.2. Docker Socket Access Risks (CR-01)
- **Threat: Container Escape / Host Compromise via Docker Socket**
  - *Risk:* Access to `/var/run/docker.sock` provides root-equivalent control over the host operating system. A process with read/write access to this socket can create privileged containers, mount the host root filesystem, and execute arbitrary code as root.
  - *Critical Security Boundary Distinction:*
    - Restricting an internal API client to HTTP `GET` requests is an **application-level convention, NOT an operating-system-enforced security boundary**.
    - If the process holding socket access is compromised, hijacked, or coerced, an adversary can issue raw HTTP `POST`/`DELETE` calls directly over the open file descriptor.
  - *Mandatory Architectural Prerequisites:*
    - Prior to introducing any Docker integration, an enforced least-privilege architecture must be established.
    - Potential future options (tentative, not approved dependencies) include:
      - A narrowly scoped, independently enforced read-only UNIX socket proxy with kernel-enforced sandboxing.
      - An isolated, unprivileged collector container/daemon.
  - *Sprint Invariant:* **Do not implement any Docker integration during this sprint.**

### 3.3. Secure Backend (Rust / Axum - Tentative) & PostgreSQL
- **Threat: Broken Object-Level Authorization (BOLA)**
  - *Risk:* Cross-project data leakage where a user from Project A accesses reports from Project B.
  - *Mitigation:*
    - Enforce tenant/project scoping on every database query: `WHERE project_id = $1 AND id = $2`.
    - Strict RBAC:
      - **Admin:** Full project and user management.
      - **Auditor:** Run audits, ingest findings, view reports.
      - **Viewer:** Read-only dashboard exploration.
- **Threat: Credential Exposure & Session Hijacking**
  - *Risk:* Weak password hashing or intercepted tokens.
  - *Mitigation:*
    - Passwords hashed using `Argon2id` (m=65536, t=3, p=4).
    - Session tokens stored in `HttpOnly`, `Secure`, `SameSite=Strict` cookies.

### 3.4. Web Frontend (Rust / Leptos WASM - Tentative)
- **Threat: Stored Cross-Site Scripting (XSS)**
  - *Risk:* Host audit strings (e.g. process names) containing HTML/JS rendered unsafely in browser DOM.
  - *Mitigation:*
    - Leptos automatically escapes interpolated strings in WebAssembly DOM nodes.
    - Enforce strict Content Security Policy (CSP).

### 3.5. Untrusted Remote Hosts & Public Distribution
- **Threat: Resource Exhaustion via Ingestion**
  - *Risk:* Ingestion of oversized or malformed JSON payloads.
  - *Mitigation:* 10MB payload size limit and JSON Schema validation before database insertion.
- **Threat: Supply Chain Contamination**
  - *Risk:* Compromised external dependencies.
  - *Mitigation:* Pure standard library for Perl (zero CPAN dependencies); pinned and audited dependencies (`cargo-audit`, `cargo-vet`) for Rust when introduced.

---

## 4. Threat Matrix & Summary

| Threat ID | Component | Threat Description | Severity | Target Phase | Defensive Control |
|---|---|---|---|---|---|
| **THREAT-01** | Bash | Sourcing `/etc/os-release` executes arbitrary code | Medium | Future Hardening Task | Parse key-value pairs without `source` |
| **THREAT-02** | Bash | `dnf check-update` hangs on interactive stdin | High | Future Hardening Task | Enforce `</dev/null` and process timeouts |
| **THREAT-03** | Bash | Symlink dereference in `permissions.sh` | Medium | Future Hardening Task | Atomic `O_NOFOLLOW` / `lstat` checks |
| **THREAT-04** | Bash | Control characters in manual JSON escaping | Low | Future Hardening Task | Validate control chars; sanitize inputs |
| **THREAT-05** | Perl | Shell injection in `sec-cli` | High | Sprint 01 | Enforce array-based process execution (`execve`) |
| **THREAT-06** | Perl | SSRF / internal scanning via `tcp-check` | Medium | Sprint 01 | Whitelist protocols, reject metadata IPs |
| **THREAT-07** | Perl | Unhandled blocking resolver deadlines in `dns` | Medium | Sprint 01 | Document implementation-dependent timeout |
| **THREAT-08** | Rust (Tentative) | Host takeover via Docker socket | Critical | Future Prerequisite | Enforced OS proxy / isolated least-privilege boundary |
| **THREAT-09** | Rust (Tentative) | BOLA / Privilege escalation in backend | High | Future Backend Phase | Tenant-isolated SQL queries + RBAC guards |
| **THREAT-10** | WASM (Tentative) | Stored XSS in audit dashboard | High | Future UI Phase | Framework auto-escaping + Strict CSP headers |
| **THREAT-11** | Backend (Tentative) | Resource exhaustion via oversized JSON | Medium | Future Backend Phase | 10MB payload limit + JSON Schema validator |
