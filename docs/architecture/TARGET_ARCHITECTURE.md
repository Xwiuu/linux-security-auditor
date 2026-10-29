# Target Architecture: Linux Security & Infrastructure Management Platform

**Status:** Tentative Architecture Baseline (Provisional Design)
**Phase:** Sprint 00 Analysis  
**Engineering Policy:** Strict YAGNI (You Aren't Gonna Need It) & Compatibility Over Elegance  
**License:** MIT  

---

## 1. Architectural Philosophy & Principles

To evolve Linux Security Auditor from a standalone Bash auditing script into an open-source Linux Security & Infrastructure Management Platform without violating strict YAGNI or breaking existing contracts, the proposed architecture adheres to the following principles:

1. **Non-Breaking Monorepo:** The existing GNU Bash codebase (`lsa`, `lib/`, `modules/`, `parsers/`, `reporters/`, `tui/`) remains intact as the baseline auditor. Existing CLI commands, options (`--format json|csv|text`), TUI, and installer/uninstaller continue to work identically.
2. **Zero-Orchestration Local Invariant:** Components must be capable of functioning locally as self-contained binaries or scripts where applicable. No component shall mandatorily require a background daemon, message broker, Kubernetes cluster, or remote server to perform basic local operations.
3. **Pragmatic Technology Allocation:**
   - **Bash:** Local host configuration auditing and interactive terminal checks.
   - **Perl:** Security engineering CLI (forensic checks, network diagnostics, hashing). *Note: Perl availability varies on minimal or containerized Linux environments.*
   - **Rust (Tentative Platform):** Strategic platform language for high-performance collectors, backend API (Axum), and reactive web frontend (Leptos / WebAssembly). Note: WebAssembly execution in browser environments requires a JavaScript bootstrap loader and associated build tooling.
4. **Decoupled Database Boundaries:** CLI tools and collectors never connect directly to PostgreSQL. PostgreSQL access is isolated strictly behind the backend service.
5. **Explicit Versioned Data Contracts:** Communication between components occurs via versioned JSON schemas, ensuring interoperability without runtime coupling.
6. **Strict YAGNI Phasing:** Multi-crate splits, background daemons, or helper processes are tentative architectural options. They will be introduced only when justified by concrete functional evidence and validated requirements.

---

## 2. Monorepo Structure (Provisional)

```
linux-security-auditor/
├── lsa                         # [Bash] Canonical entrypoint (v1.0.0 preserved)
├── lib/                        # [Bash] Finding engine, core, logger, utils
├── modules/                    # [Bash] Host audit modules (users, sudo, ssh, ...)
├── parsers/                    # [Bash] Journal and SSH auth parsers
├── reporters/                  # [Bash] Text, JSON, and CSV reporters
├── tui/                        # [Bash] Terminal interface
├── install.sh                  # [Bash] Canonical installer
├── uninstall.sh                # [Bash] Canonical uninstaller
├── scripts/
│   ├── check.sh                # Existing Bash quality gate (untouched)
│   └── check-all.sh            # (Future) Quality gate runner invoking language checks
│
├── sec-cli/                    # [Perl] Security Engineering CLI (Sprint 01 target)
│   ├── bin/
│   │   └── sec-cli             # Main Perl CLI entrypoint
│   ├── lib/
│   │   └── LSA/
│   │       ├── SecEng/
│   │       │   ├── DNS.pm      # DNS lookup
│   │       │   ├── TCP.pm      # TCP connectivity checks
│   │       │   ├── Hash.pm     # Streaming SHA-256 hashing
│   │       │   └── Logger.pm   # Structured JSON logger
│   │       └── Schema.pm       # Output JSON envelope validator
│   └── t/                      # Perl Test::More test suites
│
├── rust/                       # [Rust] Tentative Platform (Future Sprints)
│   ├── Cargo.toml              # (Tentative) Cargo workspace definition
│   └── crates/
│       ├── lsa-core/           # (Tentative) Shared models & validation logic
│       ├── lsa-collector/      # (Tentative) Read-only host telemetry binary
│       ├── lsa-backend/        # (Tentative) Axum HTTP API, Auth/RBAC, PostgreSQL storage
│       └── lsa-frontend/       # (Tentative) Leptos WebAssembly SPA
│
├── schemas/                    # JSON Schema specifications
│   ├── findings.v1.json        # Bash finding engine schema
│   ├── sec-ops.v1.json         # Perl Security Engineering schema
│   ├── collector.v1.json       # Host telemetry schema
│   └── audit-report.v2.json    # Consolidated multi-module platform report
│
└── docs/                       # Architecture, security, and development docs
```

---

## 3. Component Responsibilities & Boundaries

```
┌────────────────────────────────────────────────────────────────────────┐
│                        USER / ADMINISTRATOR                            │
└───────────┬───────────────────────────┬──────────────────────┬─────────┘
            │                           │                      │
            ▼ CLI                       ▼ CLI                  ▼ Browser
┌───────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐
│     Existing LSA      │   │     sec-cli (Perl)    │   │  Web UI (Leptos/WASM) │
│     (Bash v1.0.0)     │   │ Security Engineering  │   │     [Tentative]       │
└───────────┬───────────┘   └───────────┬───────────┘   └───────────┬───────────┘
            │                           │                           │
            │ JSON v1                   │ JSON v1                   │ HTTP REST
            ▼                           ▼                           ▼
┌────────────────────────────────────────────────────────────────────────┐
│             Platform Backend Service (Rust / Axum) [Tentative]         │
│  - Session Authentication & RBAC (Admin, Auditor, Viewer)              │
│  - Project & Target Manager                                            │
│  - Ingestion Pipeline for Bash / Perl / Collector JSON Reports         │
└───────────────────┬───────────────────────────────┬────────────────────┘
                    │                               │
                    ▼                               ▼
       ┌────────────────────────┐      ┌────────────────────────┐
       │   PostgreSQL Database  │      │  lsa-collector (Rust)  │
       │  (Users, RBAC, Audits) │      │      [Tentative]       │
       └────────────────────────┘      └────────────────────────┘
```

### 3.1. Bash Auditor (`lsa`)
- **Boundary:** Audits local Linux host configuration using GNU Bash (Bash 4+).
- **Contract:** Emits plain text, CSV, or `findings.v1.json`.
- **Invariance:** Stays 100% backward compatible. No breaking changes to existing CLI flags or scripts.

### 3.2. Security Engineering CLI (`sec-cli`, Perl)
- **Boundary:** Network diagnostics and cryptographic primitives (DNS lookup, TCP reachability, SHA-256 file hashing, structured logging).
- **Execution:** Pure standard Perl core modules (`Socket`, `IO::Socket::IP`, `Digest::SHA`, `Getopt::Long`, `JSON::PP`).
- **Dependencies:** Standard Perl core only. Note: While Perl is widely installed on standard enterprise distros, its availability varies across minimal, containerized, or appliance Linux images.
- **Contract:** Emits `sec-ops.v1.json` envelope with explicit exit codes and error structures.
- **Scope Note:** File integrity baselining and verification are deferred to a subsequent sprint.

### 3.3. Infrastructure Collector (`lsa-collector`, Rust - Tentative)
- **Boundary:** High-performance, memory-safe, read-only system metrics extraction.
- **Host Collector:** Reads `/proc`, `/sys`, and `/etc` directly.
- **YAGNI Provision:** Introduced only when proven necessary over existing shell collection.

### 3.4. Secure Backend (`lsa-backend`, Rust & Axum - Tentative)
- **Boundary:** Manages user authentication, Project Management, and RBAC authorization.
- **Storage:** Sole component authorized to connect to PostgreSQL.
- **Ingestion API:** Exposes endpoints to ingest audit JSON outputs from `lsa`, `sec-cli`, and collectors.

### 3.5. Web Frontend (`lsa-frontend`, Rust & Leptos WASM - Tentative)
- **Boundary:** Browser-based single-page application compiled to WebAssembly.
- **Runtime:** Requires a JavaScript bootstrap loader and associated build tooling in browser environments. Communicates with `lsa-backend` over JSON REST APIs.

---

## 4. Local Execution Model & Process Invocation

### 4.1. Local Execution Invariant
Each CLI component (`lsa`, `sec-cli`) is directly executable on the command line without background services:
```bash
# 1. Existing Bash auditor
./lsa audit --format json --output report.json

# 2. Perl Security Engineering CLI (Sprint 01)
./sec-cli/bin/sec-cli hash /etc/passwd --algo sha256
./sec-cli/bin/sec-cli tcp-check 127.0.0.1 22 --timeout 3
./sec-cli/bin/sec-cli dns localhost
```

### 4.2. Subprocess Handling & Timeout Policy
When invoking external processes or network operations:
1. **No Shell Interpolation:** Always invoke binaries using argument vector arrays (`execve`, `system(@args)`, `std::process::Command::new()`). Never pass concatenated strings to `/bin/sh -c`.
2. **Unified Timeout Policy:**
   - **TCP Connect Timeout:** Default is 3 seconds; maximum configurable is 10 seconds.
   - **DNS Resolver Timeout:** Implementation-dependent. Because blocking system resolver calls (e.g. C library `getaddrinfo`) cannot be guaranteed to terminate on a hard deadline across all libc/thread implementations, application-level timeout requests must not be described as guaranteeing a hard deadline without verified low-level support.
   - **Exit Code 124:** Returned only when an actual timeout condition has been established.
3. **Standardized Process Exit Codes:**
   - `0`: Success / Audit Clean.
   - `1`: Warning / Findings Detected.
   - `2`: CLI Usage / Syntax Error.
   - `3`: Environmental / Dependency Failure (permission denied, command not found).
   - `124`: Execution Timeout (only when timeout condition is positively established).

---

## 5. Host Data Collection Architecture

1. **Direct Kernel Interface Preference:** Where feasible, future native collectors read directly from `/proc` and `/sys` rather than spawning external processes.
2. **Path Sanitization & Symlink Protections:**
   - Pre-checking symlink status (e.g. `[[ -L "$file" ]]`) does **not** eliminate Time-of-Check to Time-of-Use (TOCTOU) race conditions between check and consumption.
   - True symlink race elimination requires atomic operating-system primitives (such as `O_NOFOLLOW` or `openat2(..., RESOLVE_NO_SYMLINKS)`) at the open/read boundary.

---

## 6. Docker Security Boundary & Collection Strategy

Accessing the Docker daemon socket (`/var/run/docker.sock`) carries significant security implications:

1. **High-Privilege Trust Boundary:** Access to `/var/run/docker.sock` provides root-equivalent control over the host operating system. A process with read/write access to this socket can create privileged containers, mount the host root filesystem (`-v /:/host`), and execute arbitrary code as root.
2. **Application vs. Operating System Boundaries:**
   - Restricting an internal API client to HTTP `GET` requests is an **application-level convention, NOT an operating-system-enforced security boundary**.
   - If the process holding socket access is compromised, hijacked, or coerced, an adversary can issue raw HTTP `POST`/`DELETE` calls directly over the open file descriptor.
3. **Prerequisite Least-Privilege Architecture:**
   - Before any Docker integration is introduced, a verified least-privilege architecture must be established.
   - Potential future architectural options (not approved dependencies) include:
     - An independently enforced, out-of-process read-only socket proxy with kernel-enforced isolation.
     - An isolated unprivileged daemon running with drop-privileges capabilities.
4. **Sprint Invariant:** **Do not implement any Docker integration during this sprint.**

---

## 7. Database Boundaries & Project Manager (Tentative)

The platform envisions multi-target project management and RBAC backed by PostgreSQL.

### 7.1. Database Isolation Invariant
- **No Direct CLI Connection:** Standalone scripts (`lsa`, `sec-cli`) NEVER connect to PostgreSQL.
- **Backend Ownership:** Only the backend service connects to PostgreSQL via a connection pool (`sqlx`).

### 7.2. Database Domain Boundaries
1. **Auth & Identity Domain:** `users`, `roles`, `permissions` (Argon2id password hashing).
2. **Project Management Domain:** `projects`, `targets`.
3. **Audit & Compliance Domain:** `audit_runs`, `audit_findings`.

---

## 8. Compatibility with Existing Reports

The platform preserves all existing report artifacts without alteration:
- **Bash Text Report:** [`reporters/text.sh`](file:///mnt/novovolume/Prg/linux-security-auditor/reporters/text.sh) remains the default human-readable CLI view.
- **Bash CSV Report:** [`reporters/csv.sh`](file:///mnt/novovolume/Prg/linux-security-auditor/reporters/csv.sh) schema remains unchanged.
- **Bash JSON Report:** [`reporters/json.sh`](file:///mnt/novovolume/Prg/linux-security-auditor/reporters/json.sh) output format (`{"findings": [...]}`) is registered as `findings.v1.json`.
- Future ingestion pipelines will accept `findings.v1.json` directly, converting legacy reports into platform database records without requiring modifications to existing Bash scripts.
