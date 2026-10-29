# Engineering Roadmap: Linux Security & Infrastructure Platform

**Status:** Strategic Engineering Plan  
**Policy:** Strict YAGNI & Incremental Delivery  
**Cadence:** Bi-weekly Sprints  

---

## 1. Guiding Guardrails & Anti-Patterns

To ensure architectural discipline and maintainability, all roadmap phases abide by the following non-negotiable guardrails:

- **No Microservices or Premature Distributed Systems:** The entire platform remains a modular monorepo.
- **No Message Brokers (Kafka, RabbitMQ, Redis):** IPC and backend communication rely on standard HTTP REST and direct PostgreSQL queries.
- **No Orchestration Infrastructure (Kubernetes, Helm, Swarm):** Deployments remain simple standalone binaries or systemd units.
- **No Docker Write Operations:** Docker socket access is strictly constrained to read-only container and image telemetry.
- **No Non-Core Perl Dependencies:** Perl components run on pure standard Perl 5.32+ core modules with zero external CPAN dependencies.
- **Strict Backward Compatibility:** Every release guarantees that the legacy `./lsa` CLI, TUI, and existing output formats continue to function without alteration.

---

## 2. Phase-by-Phase Evolutionary Roadmap

```
Sprint 00 (Current) ──► Sprint 01-02 ──────────► Sprint 03-04 ──────────► Sprint 05-06 ──────────► Sprint 07-08 ──────────► Sprint 09-10
[Audit Baseline]        [Perl sec-cli]           [Rust Collectors]       [Rust Backend/DB]        [WASM Frontend]          [RBAC & Projects]
- Repository audit      - DNS lookup             - Read-only /proc       - Axum REST API          - Leptos UI              - Multi-tenant
- Contracts & specs     - TCP check              - Read-only Docker      - PostgreSQL             - Findings view          - Project groups
- CI verification       - SHA-256 hash           - collector.v1.json     - findings ingestion     - Metric dashboards      - Compliance export
                        - Structured logging
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
- Implement `sec-cli tcp-check`: Non-blocking TCP connectivity test with sub-second latency and explicit timeout.
- Implement `sec-cli dns`: Forward IPv4/IPv6 DNS query resolution with explicit timeout.
- Implement `sec-cli log`: Structured JSON log formatter.
- Deliver JSON output envelope matching `sec-ops.v1.json`.
- *(Note: File integrity baselines and verification are deferred to Sprint 02).*

#### Sprint 02: File Integrity Baselining & Verification
- Implement `sec-cli integrity-init`: Recursive directory hashing with metadata capture (file mode, owner, group, SHA-256).
- Implement `sec-cli integrity-verify`: Verification against generated baseline, reporting added, removed, modified, or permission-altered files.
- Address confirmed Bash baseline risks (stdin closure `</dev/null` for `modules/updates.sh`, line-by-line parsing for `modules/host.sh`).

---

### Phase 2: Read-Only Infrastructure Collectors in Rust (Sprints 03 – 04)
*Goal: High-performance, memory-safe system and container telemetry extraction.*

#### Sprint 03: Host System Collector (`lsa-collector`)
- Initialize Rust workspace in `rust/` (`lsa-core`, `lsa-collector`).
- Implement direct `/proc` and `/sys` parsers for memory, CPU, mounted filesystems, and network sockets (eliminating shell forks).
- Safe symlink and permission handling (`O_NOFOLLOW`).
- Output JSON telemetry matching `collector.v1.json`.

#### Sprint 04: Read-Only Docker Collector
- Implement direct UNIX domain socket client for `/var/run/docker.sock`.
- Enforce compile-time HTTP GET-only guard (preventing container mutation).
- Extract container configuration, exposed ports, privileged flags, read-only rootfs status, and volume mount permissions.
- Graceful degradation when Docker is unavailable or the current user lacks socket access.

---

### Phase 3: Secure Core Backend & PostgreSQL Storage (Sprints 05 – 06)
*Goal: Centralized platform API, session authentication, and audit history.*

#### Sprint 05: Core REST Service & Database Schema
- Initialize `lsa-backend` crate using Axum and `sqlx`.
- PostgreSQL database migrations for users, projects, audit snapshots, and finding records.
- User authentication via `Argon2id` password hashing and secure cookie-based session management.

#### Sprint 06: Multi-Format Ingestion Pipeline
- Implement ingestion endpoints:
  - `POST /api/v1/projects/:id/ingest/bash` (`findings.v1.json`)
  - `POST /api/v1/projects/:id/ingest/sec-ops` (`sec-ops.v1.json`)
  - `POST /api/v1/projects/:id/ingest/collector` (`collector.v1.json`)
- Strict JSON Schema validation and 10MB payload size limit.
- Audit history querying and finding delta comparisons over time.

---

### Phase 4: Web Frontend in Rust / Leptos (Sprints 07 – 08)
*Goal: Reactive browser interface compiled to WebAssembly without NodeJS/JavaScript runtimes.*

#### Sprint 07: WASM Single-Page App & Findings Dashboard
- Initialize `lsa-frontend` crate using Leptos WebAssembly.
- Secure session login, cookie management, and CSRF protection.
- Interactive audit dashboard displaying finding counts by severity (`CRITICAL`, `HIGH`, `WARN`, `PASS`).
- Searchable and filterable data tables for the 40 audit findings.

#### Sprint 08: Infrastructure & Container Explorer
- Container security views (visualizing privileged containers and writable root filesystems).
- Visual diffs for audit history and metric timelines.
- Report export functionality (Text, JSON, CSV).

---

### Phase 5: Multi-Host Project Management & RBAC Governance (Sprints 09 – 10)
*Goal: Role-based access control and multi-environment organization.*

#### Sprint 09: Granular RBAC
- Implement RBAC authorization layer:
  - `Admin`: Full organizational control.
  - `Auditor`: Execute audits, ingest results, generate baselines.
  - `Viewer`: Read-only report exploration.
- Audit logging for administrative actions within the platform.

#### Sprint 10: Multi-Target Management & Release v2.0.0
- Target node registry (associating multiple host audits with projects).
- Compliance summary reports (CIS benchmark mapping for LSA findings).
- Comprehensive end-to-end integration testing across all platform tiers.
- Tag and release Linux Security & Infrastructure Management Platform v2.0.0.
