# Engineering Roadmap: Linux Security & Infrastructure Platform

**Status:** Strategic Engineering Plan (Provisional)
**Policy:** Strict YAGNI & Incremental Delivery  
**Cadence:** Bi-weekly Sprints  

---

## 1. Guiding Guardrails & Anti-Patterns

To ensure architectural discipline and maintainability, all roadmap phases abide by the following non-negotiable guardrails:

- **Strict Sprint Boundaries:** Sprint 01 focuses exclusively on the standalone Perl Security Engineering CLI (`sec-cli`). Existing Bash module remediations are tracked as a separate future hardening task.
- **Strict YAGNI:** The multi-crate Rust workspace, collectors, and web services are tentative architecture. They will be phased and introduced only when justified by validated functional requirements.
- **No Premature Microservices or Orchestration:** The platform remains a modular monorepo. No Kubernetes, Helm, message brokers (Kafka/RabbitMQ), or service meshes.
- **Docker Privilege Invariance:** Access to `/var/run/docker.sock` is a root-equivalent privilege boundary. An enforced least-privilege boundary (such as an independent read-only proxy) is a strict prerequisite before introducing Docker telemetry. Do not implement Docker integration in this sprint.
- **Dependency Minimization:** Perl components run on pure standard Perl 5.32+ core modules with zero external CPAN dependencies. *Note: Perl availability varies across minimal, containerized, or appliance Linux installations.*
- **Strict Backward Compatibility:** Every release guarantees that the legacy `./lsa` CLI, TUI, and existing output formats continue to function without alteration.

---

## 2. Phase-by-Phase Evolutionary Roadmap

```
Sprint 00 (Current) ──► Sprint 01 ──────────► Sprint 02 ──────────► Future Hardening ──► Future Platform (Tentative)
[Audit Baseline]        [Perl sec-cli]       [Perl Integrity]     [Bash Maintenance]   [Rust Collector / Axum / WASM]
- Repository audit      - DNS lookup         - Baseline init      - stdin </dev/null   - Read-only /proc collector
- Contracts & specs     - TCP check          - Baseline verify    - os-release parsing - Axum REST & PostgreSQL
- CI verification       - SHA-256 hash       - Delta reporting    - stat TOCTOU fix    - Leptos WASM UI
                        - JSON logging                            - JSON control chars
```

---

### Phase 0: Baseline Audit & Architectural Foundation (Sprint 00)
*Status: Complete*
- Audit the existing Bash v1.0.0 codebase.
- Execute and verify the baseline quality gate (`./scripts/check.sh </dev/null`).
- Document verified limitations (firewall-cmd dependency, unversioned JSON reports, installer repository dependence, manual JSON escaping, journal/sshlog separation).
- Establish architectural boundaries, communication contracts, and threat models.

---

### Phase 1: Security Engineering CLI in Perl (Sprints 01 – 02)
*Goal: Provide a standalone, zero-dependency forensic and networking CLI.*

#### Sprint 01: Core Primitives & Diagnostics
- Establish `sec-cli/` directory layout and pure core Perl test suite using `Test::More`.
- Implement `sec-cli hash`: Streaming SHA-256 calculation for files with byte size and mtime.
- Implement `sec-cli tcp-check`: Non-blocking TCP connectivity test with sub-second latency and explicit timeout (default 3s, max 10s).
- Implement `sec-cli dns`: Forward IPv4/IPv6 DNS query resolution with implementation-dependent timeout.
- Implement `sec-cli log`: Structured JSON log formatter.
- Deliver JSON output envelope matching `sec-ops.v1.json`.
- *(Note: File integrity baselines and verification are deferred to Sprint 02. Bash module bug fixes are tracked separately).*

#### Sprint 02: File Integrity Baselining & Verification
- Implement `sec-cli integrity-init`: Recursive directory hashing with metadata capture (file mode, owner, group, SHA-256).
- Implement `sec-cli integrity-verify`: Verification against generated baseline, reporting added, removed, modified, or permission-altered files.

---

### Maintenance Track: Existing Bash Hardening (Future Task)
*Goal: Address verified limitations and risks in the Bash v1.0.0 codebase without conflating with Perl work.*
- In `modules/updates.sh`: Enforce closed standard input (`</dev/null`) and command timeout on `dnf check-update` to eliminate interactive hanging.
- In `modules/host.sh`: Replace shell `source "$OS_RELEASE_FILE"` with safe line-by-line key extraction.
- In `modules/permissions.sh`: Address symlink dereferencing to prevent TOCTOU anomalies.
- In `reporters/json.sh`: Expand JSON escaping to cover non-printable ASCII control characters.

---

### Phase 2: Read-Only Infrastructure Collectors in Rust (Tentative Future Phase)
*Goal: High-performance, memory-safe system telemetry extraction.*
- Initialize Rust workspace in `rust/` based on validated performance requirements over shell collection.
- Implement direct `/proc` and `/sys` parsers for memory, CPU, mounted filesystems, and network sockets (eliminating shell forks).
- Safe atomic file open and permission handling (`O_NOFOLLOW`).
- Docker socket collection: Conditioned on a validated, independently enforced least-privilege boundary (such as an out-of-process read-only socket proxy).

---

### Phase 3: Secure Core Backend & PostgreSQL Storage (Tentative Future Phase)
*Goal: Centralized platform API, session authentication, and audit history.*
- Axum REST service and PostgreSQL database migrations for users, projects, audit snapshots, and finding records.
- User authentication via `Argon2id` password hashing and secure cookie-based session management.
- Multi-format ingestion pipeline for `findings.v1.json` and `sec-ops.v1.json`.

---

### Phase 4: Web Frontend in Rust / Leptos (Tentative Future Phase)
*Goal: Reactive browser interface compiled to WebAssembly.*
- Leptos WebAssembly SPA with JavaScript bootstrap loader and associated build tooling.
- Interactive audit dashboard displaying finding counts by severity (`CRITICAL`, `HIGH`, `WARN`, `PASS`).
- Searchable and filterable data tables for audit findings.
