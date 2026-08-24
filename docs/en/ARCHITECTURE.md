# WireScope architecture

[Русский](../ARCHITECTURE.md)

WireScope is a local modular monolith for network inventory, diagnostics, and auditing. It is designed for one Linux host, VM, or ARM64 appliance: API, worker, SQLite, evidence storage, and the browser UI form one device without Redis, Celery, or internal network microservices.

The main design rule is **collect facts first, interpret them later**. Packet sensors, Nmap, and protocol providers produce observations/evidence. Assessment, classification, and findings logic interpret persisted data afterwards.

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
      │    └── insights
      │
      ├── domain services
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

API and worker are separate processes. The browser/kiosk is a durable-API client. Reloading or restarting Chromium does not change job lifecycle.

## Backend composition

`backend/app.py` is the composition root. It constructs application services, groups them in `AppServices`, mounts routers, and serves the static frontend.

`backend/dependencies.py` contains the runtime dependency container. Routers receive already-created services through `Depends(get_services)` and do not become a second domain layer.

The canonical HTTP API is published below:

```text
/api/v1/...
```

`/api/...` remains a temporary compatibility alias using the same handlers, models, authorization, and scope checks. The legacy alias is hidden from OpenAPI.

## Router layout

```text
backend/routers/
├── auth.py
├── system.py
├── audits.py
├── captures.py
├── inventory.py
├── protocol.py
├── findings.py
├── reports.py
├── jobs.py
└── insights.py
```

`insights.py` does not create a second persistence model. It exposes read-only views over existing stores:

- runtime capabilities;
- active scan profile catalog;
- audit dashboard/pipeline;
- passive/active correlation summaries;
- audit-to-audit diff;
- audit-scoped evidence access.

## Environment, interfaces, and scope

`engine/environment.py` discovers host state. `engine/interfaces.py` discovers and validates interfaces. `engine/routes.py` verifies the actual route/source used for active targets. `engine/network.py` and `netctl` handle controlled host-network changes.

Observed network data and authorized active scope are separate concepts. An ARP host, DHCP server, LLDP/CDP neighbor, or VLAN tag seen passively is not automatically authorized for scanning.

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

A PCAP is decoded once. Sensors do not start one tshark process per protocol.

## Jobs and persistence

Long-running work is represented as durable jobs:

```text
queued → running → completed
   │        ├────→ failed
   │        ├────→ cancelled
   │        └────→ interrupted
   └─────────────→ cancelled
```

`JobService` owns transitions. The worker claims jobs atomically. Resource locks and worker leases live in SQLite.

SQLite is the system of record for audits, jobs/events, scopes, inventory, observations, findings, users/sessions, reports, and artifact metadata. Connections use WAL, foreign keys, a busy timeout, and short transactions; scanner processes do not hold SQL transactions open.

## Evidence store

PCAP, Nmap XML, raw provider stdout/stderr, passive-result JSON, and generated reports live in the filesystem evidence store rather than large relational BLOBs.

Artifacts are written atomically and registered with UUID, size, and SHA-256. API clients never choose filesystem paths.

Canonical artifact access is audit-scoped:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

## Inventory, correlation, and classification

Identity correlation is conservative:

1. exact MAC;
2. exact IP;
3. preserve conflicts as observations instead of silently merging assets.

Hostnames remain provenance/signals rather than sufficient evidence for aggressive identity merges.

Device classification combines OS hints, vendor data, services/ports, and naming sources. The result is stored as a confidence-rated `device_class_hint` with explainable signal sources, not as a security finding.

## Active scan profiles

Active profiles are declarative in `config/active_profiles.json` and loaded by `engine/active_profiles.py`.

The API exposes the effective catalog:

```text
GET /api/v1/scan-profiles
```

A profile defines timing, TCP/UDP coverage, service/version detection, OS detection, and timeout. Clients cannot submit arbitrary Nmap argv.

## Capabilities and readiness

`backend/capabilities.py` builds a runtime inventory of capture/decode tools, Nmap, and protocol providers.

Core readiness depends on the components required for the appliance to function. An unavailable optional provider does not force the whole WireScope instance into `not_ready`.

The UI reads:

```text
GET /api/v1/capabilities
```

The response also reports the effective web listener: bind host/port, TLS, and trust-proxy state.

## Dashboard and pipeline

The dashboard has no dedicated table. It aggregates persisted jobs, inventory, and findings:

```text
GET /api/v1/audits/{audit_id}/dashboard
```

Pipeline stages are derived from durable jobs:

```text
passive → discovery → protocol → findings → report
```

## Audit diff

Two audits can be compared from persisted state:

```text
GET /api/v1/audits/{new_id}/diff?against={old_id}
```

The diff covers assets, open services, and findings. Cross-audit identity uses the strongest stable signal available, primarily MAC and then IP/name fallbacks.

## Findings and reports

The findings engine consumes normalized observations and inventory, applies versioned rules, and produces findings with severity, confidence, rationale, recommendation, and evidence links.

Report generation does not contact the network. The canonical document is `audit-report v1` JSON. Self-contained HTML and Markdown are rendered from it. PDF is not implemented yet.

## Frontend

The established wizard remains in `frontend/app.js`. Operator insights are isolated in `frontend/enhancements.js` and `enhancements.css` so the primary workflow does not keep growing.

The panel exposes:

- dashboard/pipeline;
- capabilities and listener state;
- scan profiles;
- audit diff;
- evidence viewer.

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

The Python backend does not receive packet-capture capabilities. WireScope does not elevate Nmap itself.

## Deployment

A normal appliance must be reachable through whichever configured interface is available to the operator, so application settings, installer, and upgrade path default to:

```text
0.0.0.0:8000
```

The local kiosk still opens `http://127.0.0.1:8000/`.

Loopback-only deployment remains an explicit option:

```bash
sudo ./packaging/install.sh --bind-host 127.0.0.1
```

Firewall restrictions, direct TLS, or a reverse proxy can be added to match a particular network without changing WireScope's internal architecture.

## CI and testing

GitHub Actions on Python 3.11 installs the project, compiles Python sources, and runs the default `pytest` suite. Live-network and browser-specific checks remain opt-in where appropriate.

## Remaining technical debt

- PDF export;
- a dedicated security audit-log table;
- policy-driven retention/deletion for completed audits/evidence;
- automatic retry for terminal/interrupted jobs;
- release validation of tshark/provider compatibility across supported distro package versions.
