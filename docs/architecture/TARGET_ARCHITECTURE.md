# Target Architecture: Linux Security & Infrastructure Management Platform

**Status:** Proposed Architecture Baseline  
**Phase:** Sprint 00 Analysis  
**Engineering Policy:** Strict YAGNI (You Aren't Gonna Need It) & Compatibility Over Elegance  
**License:** MIT  

---

## 1. Architectural Philosophy & Principles

To evolve Linux Security Auditor from a standalone Bash auditing script into an open-source Linux Security & Infrastructure Management Platform without violating strict YAGNI or breaking existing contracts, the target architecture adheres to six bedrock principles:

1. **Non-Breaking Monorepo:** The existing Bash codebase (`lsa`, `lib/`, `modules/`, `parsers/`, `reporters/`, `tui/`) remains intact as the baseline auditor. Existing CLI commands, options (`--format json|csv|text`), TUI, and installer/uninstaller continue to work identically.
2. **Zero-Orchestration Local Invariant:** Every component must function locally as a self-contained binary or script. No component shall require a background daemon, message broker, Kubernetes cluster, or remote server to perform its primary function.
3. **Strict Separation of Concerns:**
   - **Bash:** Host configuration auditing and interactive terminal checks.
   - **Perl:** Security engineering CLI (forensic checks, network diagnostics, hashing).
   - **Rust (Collector):** High-performance read-only host and Docker infrastructure data extraction.
   - **Rust (Backend):** Axum REST API, session authentication, RBAC, project management, and PostgreSQL database interaction.
   - **Rust (Frontend):** Leptos WebAssembly SPA providing reactive dashboards without external JavaScript runtimes.
4. **Read-Only Infrastructure Invariance:** Under no circumstances will Docker collectors or host collectors perform mutating operations (`POST`, `PUT`, `DELETE`, container exec, image build, network creation). Access to the Docker socket (`/var/run/docker.sock`) is strictly constrained to read-only `GET` endpoints.
5. **Decoupled Database Boundaries:** CLI tools and collectors never connect to PostgreSQL. PostgreSQL is isolated strictly behind the Rust Axum backend.
6. **Explicit Versioned Data Contracts:** Communication between components occurs via versioned JSON schemas, ensuring interoperability without runtime coupling.

---

## 2. Monorepo Structure

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
├── sec-cli/                    # [Perl] Security Engineering CLI
│   ├── bin/
│   │   └── sec-cli             # Main Perl CLI entrypoint
│   ├── lib/
│   │   └── LSA/
│   │       ├── SecEng/
│   │       │   ├── DNS.pm      # DNS lookup with strict timeouts
│   │       │   ├── TCP.pm      # TCP connectivity checks
│   │       │   ├── Hash.pm     # Streaming SHA-256 hashing
│   │       │   └── Logger.pm   # Structured JSON logger
│   │       └── Schema.pm       # Output JSON envelope validator
│   └── t/                      # Perl Test::More test suites
│
├── rust/                       # [Rust] Platform Backend, Collector & Web UI
│   ├── Cargo.toml              # Cargo workspace definition
│   └── crates/
│       ├── lsa-core/           # Shared models, JSON schemas, validation logic
│       ├── lsa-collector/      # Read-only host & Docker socket collector binary
│       ├── lsa-backend/        # Axum HTTP API, Auth/RBAC, PostgreSQL storage
│       └── lsa-frontend/       # Leptos WebAssembly SPA
│
├── schemas/                    # JSON Schema specifications
│   ├── findings.v1.json        # Bash finding engine schema
│   ├── sec-ops.v1.json         # Perl Security Engineering schema
│   ├── collector.v1.json       # Host & Docker telemetry schema
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
│     (Bash v1.0.0)     │   │ Security Engineering  │   │     [lsa-frontend]    │
└───────────┬───────────┘   └───────────┬───────────┘   └───────────┬───────────┘
            │                           │                           │
            │ JSON v1                   │ JSON v1                   │ HTTP REST
            ▼                           ▼                           ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  Platform Backend Service (Rust / Axum)                │
│                            [lsa-backend]                               │
│  - Session Authentication & RBAC (Admin, Auditor, Viewer)              │
│  - Project & Target Manager                                            │
│  - Ingestion Pipeline for Bash / Perl / Collector JSON Reports         │
└───────────────────┬───────────────────────────────┬────────────────────┘
                    │                               │
                    ▼                               ▼
       ┌────────────────────────┐      ┌────────────────────────┐
       │   PostgreSQL Database  │      │  lsa-collector (Rust)  │
       │  (Users, RBAC, Audits) │      │  - Read-only /proc     │
       └────────────────────────┘      │  - Read-only Docker    │
                                       └────────────────────────┘
```

### 3.1. Bash Auditor (`lsa`)
- **Boundary:** Audits local Linux host configuration.
- **Contract:** Emits plain text, CSV, or `findings.v1.json`.
- **Invariance:** Stays 100% backward compatible. No breaking changes to existing CLI flags or scripts.

### 3.2. Security Engineering CLI (`sec-cli`, Perl)
- **Boundary:** Network diagnostics and cryptographic primitives (DNS lookup, TCP reachability, SHA-256 file hashing, structured logging).
- **Execution:** Pure standard Perl core modules (`Socket`, `IO::Socket::IP`, `Digest::SHA`, `Getopt::Long`, `JSON::PP`).
- **Zero External Dependencies:** No CPAN installation required. Standard Perl 5.32+ on any Linux distribution.
- **Contract:** Emits `sec-ops.v1.json` envelope with explicit exit codes and error structures.
- **Scope Note:** File integrity baselining and verification are scheduled for a subsequent sprint.

### 3.3. Infrastructure Collector (`lsa-collector`, Rust)
- **Boundary:** High-performance, memory-safe, read-only system metrics and Docker container metadata.
- **Host Collector:** Reads `/proc`, `/sys`, and `/etc` with non-blocking I/O.
- **Docker Collector:** Communicates with `/var/run/docker.sock` over a local UNIX domain socket via HTTP `GET` only. Never modifies containers or images.

### 3.4. Secure Backend (`lsa-backend`, Rust & Axum)
- **Boundary:** Manages user authentication, Project Management, and RBAC authorization.
- **Storage:** Sole component authorized to connect to PostgreSQL.
- **Ingestion API:** Exposes endpoints to ingest audit JSON outputs from `lsa`, `sec-cli`, and `lsa-collector`.

### 3.5. Web Frontend (`lsa-frontend`, Rust & Leptos WASM)
- **Boundary:** Browser-based single-page application compiled to WebAssembly.
- **Security:** Renders data strictly inside the browser sandbox; communicates with `lsa-backend` over JSON REST APIs with CSRF and Bearer token protection.

---

## 4. Local Execution Model & Process Invocation

### 4.1. Local Execution Invariant
Each CLI component (`lsa`, `sec-cli`, `lsa-collector`) is directly executable on the command line without background services:
```bash
# 1. Existing Bash auditor
./lsa audit --format json --output report.json

# 2. Perl Security Engineering CLI (Sprint 01)
./sec-cli/bin/sec-cli hash /etc/passwd --algo sha256
./sec-cli/bin/sec-cli tcp-check 127.0.0.1 22 --timeout 3
./sec-cli/bin/sec-cli dns localhost --timeout 2

# 3. Rust Collector (Future)
./rust/target/release/lsa-collector --docker-only --format json
```

### 4.2. Safe Subprocess Handling & Error Propagation
When any component must invoke system binaries (e.g., `visudo`, `ss`, `ip`):
1. **No Shell Interpolation:** Always invoke binaries using argument vector arrays (`execve`, `system(@args)`, `std::process::Command::new()`). Never pass concatenated strings to `/bin/sh -c`.
2. **Explicit Timeouts:** Every external process invocation must be bounded by a non-blocking timeout (e.g., `alarm` in Perl, `tokio::time::timeout` in Rust). If a process exceeds the deadline, it is terminated with `SIGTERM` followed by `SIGKILL`, returning exit code `124`.
3. **Standardized Process Exit Codes:**
   - `0`: Success / Audit Clean (no high/critical findings).
   - `1`: Warning / Findings Detected (audit identified policy violations).
   - `2`: CLI Usage / Syntax Error (invalid parameters or arguments).
   - `3`: Environmental / Dependency Failure (permission denied, command not found).
   - `124`: Execution Timeout.

---

## 5. Host Data Collection Architecture

```
Host Operating System
├── /proc/             ──[Direct Read-Only VFS]──► lsa-collector (Rust)
│   ├── /proc/cpuinfo
│   ├── /proc/meminfo
│   ├── /proc/net/tcp
│   └── /proc/[pid]/...
│
├── /etc/              ──[Read-Only File Checks]──► lsa (Bash) / sec-cli (Perl)
│   ├── /etc/passwd
│   ├── /etc/shadow
│   └── /etc/ssh/sshd_config
│
└── /var/run/docker.sock ──[GET Only over UDS]──► lsa-collector (Rust)
```

1. **Direct Kernel Interface Preference:** Where feasible, Rust collectors read directly from `/proc` and `/sys` rather than spawning external processes (`ps`, `ss`, `uptime`). This eliminates process creation overhead and prevents PATH spoofing.
2. **Path Sanitization & Symlink Protections:**
   - Paths must be validated against directory traversal (`..`).
   - Use `O_NOFOLLOW` when opening sensitive system files to prevent symlink race conditions (TOCTOU).

---

## 6. Read-Only Docker Collection Strategy

Accessing Docker information carries significant security risks if write operations are permitted. The target platform applies a strict read-only policy:

1. **UNIX Domain Socket Transport:** Connect to `unix:///var/run/docker.sock` directly via an HTTP client over UNIX sockets.
2. **HTTP GET-Only Whitelist:**
   - Allowed endpoints:
     - `GET /v1.43/info` (Docker daemon configuration and OS info)
     - `GET /v1.43/version` (API and engine version)
     - `GET /v1.43/containers/json?all=true` (Listing active and stopped containers)
     - `GET /v1.43/containers/{id}/json` (Detailed container inspection: security options, mounted volumes, read-only rootfs)
     - `GET /v1.43/images/json` (Image inventory)
   - Disallowed operations:
     - Any `POST`, `PUT`, `DELETE` request.
     - `POST /containers/create`, `POST /containers/{id}/start`, `POST /containers/{id}/exec`.
     - Direct connection hijacking (`/attach`, `/exec/{id}/start`).
3. **Graceful Degradation:** If `/var/run/docker.sock` does not exist or the current user lacks socket permissions, the collector outputs a structured status indicating Docker is not auditable.

---

## 7. Database Boundaries & Project Manager

The platform introduces multi-target project management and RBAC, backed by PostgreSQL.

### 7.1. Database Isolation Invariant
- **No Direct CLI Connection:** Standalone scripts (`lsa`, `sec-cli`) NEVER connect to PostgreSQL.
- **Backend Ownership:** Only `lsa-backend` connects to PostgreSQL via a connection pool (`sqlx`).

### 7.2. Database Domain Boundaries
1. **Auth & Identity Domain:**
   - `users`: User identity, password hash (`Argon2id`), account status.
   - `roles`: Role definitions (`Admin`, `Auditor`, `Viewer`).
   - `permissions`: Fine-grained privileges (`project:read`, `audit:run`, `report:export`).
2. **Project Management Domain:**
   - `projects`: Logical organizational units (e.g., "Production Edge Clusters", "Internal Infrastructure").
   - `targets`: Registered nodes (hostname, IP, OS, environment tags).
3. **Audit & Compliance Domain:**
   - `audit_runs`: Execution metadata (timestamp, target_id, triggered_by, status).
   - `audit_findings`: Normalized finding records matching `findings.v1.json`.
   - `docker_snapshots`: Read-only container security posture assessments.

---

## 8. Compatibility with Existing Reports

The platform preserves all existing report artifacts without alteration:
- **Bash Text Report:** `reporters/text.sh` output remains the default human-readable CLI view.
- **Bash CSV Report:** `reporters/csv.sh` schema (`id,category,severity,title,description,expected,actual,recommendation`) remains unchanged.
- **Bash JSON Report:** `reporters/json.sh` output format (`{"findings": [...]}`) is registered as `findings.v1.json`.
- The Rust backend ingestion engine accepts `findings.v1.json` directly, converting legacy reports into platform database records without requiring any migration of existing Bash scripts.
