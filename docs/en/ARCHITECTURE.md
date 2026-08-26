# WireScope architecture

[Русский](../ARCHITECTURE.md)

WireScope is a local modular monolith for network inventory, diagnostics, and auditing. API, worker, SQLite, evidence storage, and the browser UI form one Linux appliance without Redis, Celery, or internal network microservices.

The main design rule is **persist facts first, interpret them afterwards**. Packet sensors, Nmap, protocol providers, and management-plane providers create observations/evidence. Inventory, topology, assessment, classification, findings, and reports operate on those persisted facts.

## High-level layout

```text
browser / kiosk
      │
      ▼
FastAPI /api/v1
      │
      ├── auth / network / scope
      ├── audits / jobs / captures
      ├── inventory / protocol / findings / reports
      ├── traffic analysis / topology
      ├── diagnostics / lifecycle / audit log
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
                    ├── traffic analysis
                    ├── SNMP/SSH topology enrichment
                    ├── findings evaluation
                    └── report generation
```

API and worker are separate processes. The browser/kiosk is a durable API client; restarting Chromium does not alter job lifecycle.

## Backend composition

`backend/app.py` is the composition root. It constructs `AppServices`, mounts routers, installs middleware, and serves the frontend.

The canonical HTTP API is:

```text
/api/v1/...
```

`/api/...` remains a compatibility alias using the same handlers, models, authorization, and scope checks.

## Router layout

Major domain routers live under `backend/routers/`:

```text
auth.py
system.py
operations.py
audits.py
captures.py
inventory.py
protocol.py
findings.py
reports.py
jobs.py
topology.py
```

`topology.py` exposes read-only canonical/global/history topology and auditor-only SNMP/SSH management enrichment.

## Environment, interfaces, and scope

`engine/environment.py` collects Linux host state, including interface context, routes, and available DHCP lease hints. `engine/interfaces.py` discovers and validates interfaces. `engine/routes.py` verifies route/source for active targets. `engine/network.py` and `netctl` handle controlled host-network changes.

Observed network data and authorized scan scope always remain separate:

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
active provider
```

A passively observed ARP host, DHCP server, LLDP neighbour, VLAN tag, or SNMP-discovered subnet never becomes an automatically authorized active target.

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

A PCAP is decoded once; sensors do not spawn one `tshark` process per protocol.

## Traffic Analysis

A retained PCAP can be analyzed by a separate durable job without starting another capture.

The `traffic-analysis` result contains diagnostics and a normalized communications graph. That graph can be explicitly attached to Network Topology through `traffic_analysis_job_id`; the latest PCAP is never mixed automatically.

## Network Topology

Topology is a backend domain over persisted evidence, not frontend state.

```text
persisted inventory / environment / passive / management / traffic
                         ↓
                 canonical topology
                         ↓
              coverage / claimability
                         ↓
       structural · L2 · L3 · Traffic · all evidence
```

Modules under `topology/` cover canonical graph assembly, upstream/route projection, SNMP projection, read-only SSH management projection, source health, coverage/claimability, structural presentation metadata, global retained-audit topology, and historical comparison.

### Canonical graph and presentation

Canonical topology retains the full evidence graph. Structural presentation does not rewrite the source of truth; it may hide or group directed broadcasts, link-local noise, and PCAP-only external endpoints so the main screen remains an infrastructure-oriented diagram.

This provides both an operator-friendly map and complete JSON/evidence views.

### Evidence sufficiency

`coverage` is not a percentage of the real network discovered. It reports whether retained evidence supports claims about inventory, L3, L2, traffic, VLAN, Wi-Fi, and hypervisor context.

Statuses are:

```text
sufficient
partial
missing
```

`missing` means “WireScope cannot prove this class of relationship,” not “the relationship does not exist.”

### L3 and multi-homed hosts

The gateway of the selected audit interface comes only from interface-specific persisted evidence:

- per-interface default route;
- DHCP router option;
- management-plane evidence;
- bounded route trace.

A host-wide default route on another NIC is not projected into the selected audit network. Addresses such as `.1`, `.254`, or `.11` are never guessed.

### Management-plane enrichment

SNMP and SSH are optional active management sources and require operator-confirmed scope.

SNMP consumes standard IF/IP/BRIDGE/Q-BRIDGE/LLDP MIBs when the target exposes them.

The SSH provider targets Linux/OpenWrt-like devices and is not a generic remote shell. Remote commands are fixed to an `ip/bridge/iw` allowlist, strict host-key verification is mandatory, and no arbitrary operator command field exists.

SNMP/SSH credentials use a consume-once runtime spool and are not persisted as plaintext topology evidence.

A subnet learned through management evidence remains `active_scope=false`.

### Source health

If an expected job-backed route/SNMP/SSH artifact cannot be included, topology can remain readable while becoming explicitly partial:

```json
{
  "partial": true,
  "source_errors": []
}
```

Errors are sanitized: credentials, filesystem paths, and raw exception text are not exposed.

See [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md) for the full model.

## Jobs, persistence, and recovery

Long-running work is represented as durable jobs:

```text
queued → running → completed
   │        ├────→ failed
   │        ├────→ cancelled
   │        └────→ interrupted
   └─────────────→ cancelled
```

`JobService` owns transitions. The worker claims jobs atomically. Resource locks and heartbeat live in SQLite.

After restart, running jobs become `interrupted` and stale locks are released. Explicit retry creates a new durable job without rewriting the source history.

Credentialed `snmp_topology` and `ssh_topology` jobs are an exception to generic retry: old consume-once credential references are never reused; the operator starts enrichment again with fresh credentials.

SQLite is the system of record for audits, jobs/events, scopes, inventory, observations, findings, reports, users/sessions, operational events, and artifact metadata. Connections use WAL, foreign keys, busy timeout, and short transactions.

## Evidence store and retention

PCAP, Nmap XML, protocol raw output, management results, and generated reports live in the filesystem evidence store while metadata lives in SQLite.

Artifacts are written atomically and registered with UUID, size, and SHA-256. Clients never select filesystem paths directly.

Canonical access is audit-scoped:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Aged raw artifacts are removed only through explicit retention/cleanup. Normalized inventory/findings/reports are not automatically deleted.

## Inventory, correlation, and classification

Identity correlation remains conservative:

1. exact MAC;
2. exact IP;
3. conflicts are preserved rather than hidden by aggressive merge.

Hostname is additional signal/provenance, not sufficient identity evidence.

Device classification (`server-like`, `workstation-like`, `network-device-like`, `printer-like`, `iot-like`, `unknown`) remains an explainable hint rather than a finding.

## Findings and reports

The findings engine consumes normalized observations/inventory and applies versioned rules to create findings with severity, confidence, rationale, recommendation, and evidence links.

Report generation never contacts the network. `audit-report v1` JSON is canonical; HTML and Markdown are rendered from it.

## Operational audit log

Operational events are separate from job events. Stored fields include actor/role, action, normalized path, HTTP status, client IP, and audit id.

Request bodies, passwords, session tokens/cookies, and provider stdout are not copied into the operational log.

## Capabilities, readiness, and diagnostics

`backend/capabilities.py` separates core readiness from optional providers.

Core readiness requires SQLite/migrations, a healthy worker, and base packet-capture tools. Missing SNMP/SSH or another optional provider does not make the whole appliance `not_ready`.

```text
GET /api/v1/capabilities
GET /api/v1/diagnostics
GET /api/v1/ready
```

## Frontend

The frontend remains framework-free. The primary wizard lives in `frontend/app.js`; additional functionality is split into domain-specific modules.

Topology UI uses a base renderer plus hardening/presentation extensions. Browser state is presentation-only; the source of truth remains backend/SQLite/evidence.

Root HTML uses cache-busting asset versions so kiosk Chromium does not keep stale topology JS/CSS after upgrade.

## Backup and restore

`appliance/backup.py` uses the SQLite backup API to produce consistent snapshots from a WAL database. Evidence can be copied with the database.

Restore validates the backup using `PRAGMA integrity_check` before replacing the working database.

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

The Python backend does not receive packet-capture capabilities. WireScope does not elevate Nmap itself. SNMP/SSH management providers also run in the worker without turning the API into a root process.

## Deployment

The normal appliance listens on:

```text
0.0.0.0:8000
```

The local kiosk opens `http://127.0.0.1:8000/`. Loopback-only deployment remains explicit.

## CI and current boundary

GitHub Actions on Python 3.11 run compileall, the default pytest suite, Chromium regression, wheel build, and installed-wheel smoke outside the source tree.

Network Topology v1.2 passed live smoke on an upgraded WireScope VM. SNMP/SSH vendor-specific interoperability remains additional operational validation as managed devices become available; missing management evidence must remain visible as `missing/partial`, never replaced by guesses.

The next major subsystem is **v1.3 Global Correlation Analysis**: deterministic correlation of persisted inventory/findings/Traffic Analysis/Network Topology without new network I/O.

## Later work

Non-blocking future work includes PDF export, more protocol modules, CVE enrichment, scheduled audits, cross-site topology history, hypervisor-specific topology providers, vendor-specific management adapters, further frontend decomposition, removal of the `/api/*` compatibility alias, and a broader distro/architecture/tshark CI matrix.