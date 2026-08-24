# WireScope architecture

[Русский](../ARCHITECTURE.md)

WireScope is a local modular monolith for network inventory, diagnostics, and auditing. API, worker, SQLite, evidence storage, and the browser UI form one Linux appliance without Redis, Celery, or internal network microservices.

The main design rule is **persist facts first, interpret them afterwards**. Packet sensors, Nmap, and protocol providers create observations/evidence. Assessment, classification, and findings logic operate on those persisted facts.

## High-level layout

```text
browser / kiosk
      │
      ▼
FastAPI /api/v1
      │
      ├── routers
      │    ├── auth / system / network / scope
      │    ├── audits / jobs / captures
      │    ├── inventory / protocol / findings / reports
      │    ├── insights
      │    └── operations
      │
      ├── domain / lifecycle services
      │
      ├──────── SQLite WAL
      │
      └──────── evidence store
                    ▲
                    │
                  worker
                    ├── passive discovery
                    ├── packet capture
                    ├── active discovery
                    ├── protocol audits
                    ├── findings evaluation
                    └── report generation
```

API and worker are separate processes. The browser/kiosk is a client of durable state; restarting Chromium does not alter job lifecycle.

## Backend composition

`backend/app.py` is the composition root. It constructs `AppServices`, mounts routers, installs operational middleware, and serves the frontend.

The canonical API is `/api/v1/...`. `/api/...` remains a hidden compatibility alias using the same handlers, models, authorization, and scope checks.

## Router layout

```text
backend/routers/
├── auth.py
├── system.py
├── insights.py
├── operations.py
├── audits.py
├── captures.py
├── inventory.py
├── protocol.py
├── findings.py
├── reports.py
└── jobs.py
```

`insights.py` provides read-only views such as capabilities, profiles, dashboard, correlations, diff, and audit-scoped evidence.

`operations.py` exposes the appliance lifecycle surface: diagnostics, operational audit log, retention/cleanup, and durable job retry.

## Environment, interfaces, and scope

`engine/environment.py` discovers host state. `engine/interfaces.py` validates interfaces. `engine/routes.py` verifies the actual route/source for active targets. `engine/network.py` and `netctl` handle controlled host-network changes.

Observed network data and authorized scan scope remain separate:

```text
passive/environment evidence
        ↓
scope proposal
        ↓
operator confirmation
        ↓
immutable confirmed scope
        ↓
worker revalidation
        ↓
Nmap provider
```

## Passive pipeline

```text
validated interface
      ↓
dumpcap → bounded PCAP
      ↓
tshark -T ek
      ↓
normalized PacketRecord
      ↓
in-process sensors
      ↓
assessment + inventory observations
```

A PCAP is decoded once; sensors do not spawn one tshark process per protocol.

## Jobs, persistence, and recovery

Long-running work is represented as durable jobs:

```text
queued → running → completed
   │        ├────→ failed
   │        ├────→ cancelled
   │        └────→ interrupted
   └─────────────→ cancelled
```

`JobService` owns state transitions. The worker claims jobs atomically. Resource locks and worker heartbeat live in SQLite.

If a process restart interrupts a running job, recovery marks it `interrupted` and releases stale locks. A terminal job is never rewritten back to queued. Explicit retry creates a new durable job using the same parameters:

```text
failed/interrupted/cancelled job
        │ operator retry
        ▼
new queued job
```

Source/replacement linkage is preserved in job events. This is stage-level recovery, not reconstruction of a dead subprocess.

SQLite is the system of record for audits, jobs/events, scopes, inventory, observations, findings, users/sessions, reports, operational events, and artifact metadata. Connections use WAL, foreign keys, a busy timeout, and short transactions.

## Operational audit log

`backend/audit_log.py` stores append-only operational events separately from job events.

Middleware records significant mutating HTTP operations after execution with actor/role, normalized API path, HTTP status, client IP, and audit id when available.

Request bodies, passwords, cookies/session tokens, and provider output are never copied into the operational table.

Logging failure does not turn an otherwise successful operator action into an outage; database and migration health are independently visible through diagnostics.

## Evidence store and retention

PCAP, Nmap XML, protocol raw output, passive-result JSON, and generated reports live in the filesystem evidence store rather than relational BLOBs.

Artifacts are written atomically and registered with UUID, size, and SHA-256. Canonical access is audit-scoped:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

`backend/lifecycle.py` separates normalized history from large raw artifacts. Inventory/findings/reports are not automatically deleted. Aged PCAP/Nmap XML/protocol output becomes a cleanup candidate and is removed only after explicit confirmation.

Cleanup removes both the file and artifact metadata row. Preview mode changes nothing.

## Inventory, correlation, and classification

Identity correlation remains conservative: exact MAC, then exact IP; conflicts are preserved instead of silently merging assets. Hostnames remain provenance/signals rather than sufficient merge evidence.

Device classification combines OS hints, vendor data, services/ports, and naming sources and stores a confidence-rated hint with explainable signals.

## Active scan profiles

Active profiles live in `config/active_profiles.json` and are loaded by `engine/active_profiles.py`.

```text
GET /api/v1/scan-profiles
```

Profiles define timing, TCP/UDP coverage, service/version detection, OS detection, and timeout. Clients cannot submit arbitrary Nmap argv.

## Capabilities, readiness, and diagnostics

`backend/capabilities.py` builds runtime tool inventory. Core readiness requires SQLite/migrations, worker, and the base packet-capture tools; optional providers may be unavailable without making the entire appliance `not_ready`.

```text
GET /api/v1/capabilities
GET /api/v1/diagnostics
```

Diagnostics adds SQLite `quick_check`, disk/evidence usage, retention, platform/runtime checks, and recent operational events.

## Dashboard and diff

Dashboard derives state from persisted jobs, inventory, and findings:

```text
GET /api/v1/audits/{audit_id}/dashboard
```

Pipeline:

```text
passive → discovery → protocol → findings → report
```

Audit diff is also computed from persisted state:

```text
GET /api/v1/audits/{new_id}/diff?against={old_id}
```

## Findings and reports

The findings engine consumes normalized observations/inventory and creates confidence-rated findings with evidence links. Report generation never contacts the network. `audit-report v1` JSON is canonical; self-contained HTML and Markdown are rendered from it.

## Frontend

The primary wizard remains in `frontend/app.js`. Additional operator functionality is isolated:

```text
frontend/enhancements.js   dashboard / diff / evidence / Markdown
frontend/operations.js     diagnostics / retention / retry / audit log
```

This lets operator views evolve without rewriting the primary audit workflow.

## Backup and restore

`appliance/backup.py` uses the SQLite backup API so a consistent snapshot can be produced from a WAL database. Evidence can be copied with the database.

Restore verifies the backup with `PRAGMA integrity_check` before replacing the working database; evidence is restored separately.

## Privilege boundary

```text
unprivileged wirescope-api
unprivileged wirescope-worker
          │
          ▼
/usr/bin/dumpcap
root:wireshark 0750
cap_net_admin,cap_net_raw=eip
```

The Python backend does not receive packet-capture capabilities, and WireScope does not elevate Nmap itself.

## Deployment

Application settings, argparse, installer, and upgrade entrypoints default to:

```text
0.0.0.0:8000
```

The local kiosk still opens `http://127.0.0.1:8000/`. Loopback-only deployment remains an explicit option.

## CI and release boundary

GitHub Actions on Python 3.11 installs the project, compiles Python sources, and runs the default `pytest` suite. Live-network/browser/platform checks remain opt-in where necessary.

The first-version finish line is defined by [RELEASE_READINESS.md](RELEASE_READINESS.md), not by the absence of new feature ideas. After green CI, the last mandatory gate is a smoke test on an actually upgraded appliance.

## Post-1.0 work

Useful but non-blocking work includes PDF export, more protocol modules, topology/CVE enrichment, scheduled audits, deeper cross-audit identity history, further frontend decomposition, removing the `/api/*` compatibility alias, and a broader distro/architecture CI matrix.
