# WireScope architecture

[Русский](../ARCHITECTURE.md)

WireScope is a local modular monolith for network inventory, diagnostics, and security auditing. It is designed for a single Linux host or VM: API, worker, SQLite, evidence storage, and the browser UI form one appliance without Redis, Celery, or internal network microservices.

The main design rule is simple: **collect facts first, interpret them later**. Packet sensors, Nmap, and protocol providers produce observations and evidence. Assessment and findings logic interpret that stored data.

## High-level layout

```text
browser / kiosk
      │ HTTP + session cookie
      ▼
FastAPI
      │
      ├── backend/routers/
      │      ├── auth
      │      ├── system / network / scope
      │      ├── audits
      │      ├── captures
      │      ├── inventory
      │      ├── protocol audits
      │      ├── findings
      │      ├── reports
      │      └── jobs
      │
      ├── domain services
      │      ├── JobService
      │      ├── InventoryService
      │      ├── AuthService
      │      ├── NetworkService
      │      └── stores
      │
      ├──────────── SQLite WAL
      │
      └──────────── evidence store
                        ▲
                        │
                     worker
                        │
                        ├── passive discovery
                        ├── packet capture
                        ├── active discovery
                        ├── protocol audits
                        ├── findings evaluation
                        └── report generation
```

API and worker are separate processes. The browser or kiosk is a separate client. Restarting Chromium does not affect a running job, and restarting the API does not erase durable job state.

## Backend

### `backend/app.py`

`backend/app.py` is the composition root. It no longer contains the application's large route surface.

It has four responsibilities:

1. construct or accept application services;
2. collect them into `AppServices`;
3. attach API routers;
4. mount the frontend and static files.

Dependencies are available as `application.state.services`. Existing `application.state.jobs`, `.inventory`, `.evidence`, and related attributes are retained for compatibility with tests and in-process integrations.

### `backend/dependencies.py`

`AppServices` is the runtime dependency container used by the FastAPI layer. Routers receive it through `Depends(get_services)` instead of rebuilding services or importing global singletons.

This is intentionally not a DI framework. It is only an explicit container for services that already exist for the lifetime of the application.

### `backend/routers/`

HTTP routes are grouped by domain:

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
└── jobs.py
```

A router is not a second domain layer. Its job is to parse the HTTP request, call the existing service, and translate the result or error into the API contract.

Shared response/error conversion lives in `backend/http.py`; the common authorization guard lives in `backend/security.py`.

## API versioning

The canonical API is published as:

```text
/api/v1/...
```

For example:

```text
GET  /api/v1/health
POST /api/v1/audits
GET  /api/v1/jobs/{job_id}
```

For a gradual migration, the same `api_router` is also mounted below `/api`. The legacy prefix remains functional for the current frontend and existing clients, but it is excluded from the OpenAPI schema.

There are therefore not two API implementations:

```text
/api/v1 ─┐
         ├── same routers / same handlers / same services
/api    ─┘
```

The authorization guard normalizes both prefixes and applies the same public/auditor policy. See [API.md](API.md).

## Environment, interfaces, and network

`engine/environment.py` discovers Linux host context through ordinary system sources such as `ip -j addr`, `ip -j route`, `/sys/class/net`, resolver configuration, and the hostname.

`engine/interfaces.py` owns interface discovery and validation. Unknown, policy-denied, or down interfaces are rejected before capture or scanning starts.

`engine/network.py` and appliance `netctl` handle controlled network configuration changes. The API does not execute arbitrary user-supplied shell commands.

`engine/routes.py` verifies which interface and source address actually route to a confirmed target.

## Scope

Observed network data and authorized scope are different things.

Passive analysis may see an ARP address, DHCP server, LLDP/CDP neighbor, or VLAN tag. None of those observations authorizes active scanning by itself.

Active discovery follows this path:

```text
operator request
      ↓
ScopeValidator
      ↓
address-count / prohibited-range checks
      ↓
route + interface validation
      ↓
immutable confirmed scope
      ↓
worker
      ↓
Nmap provider
```

`0.0.0.0/0`, `::/0`, multicast ranges, and uncontrolled IPv6 expansion are rejected. Address limits depend on the selected profile.

## Passive pipeline

A normal passive audit uses a fixed pipeline:

```text
validated interface
      ↓
dumpcap → bounded PCAP
      ↓
tshark -T ek → line-oriented decode
      ↓
normalized PacketRecord
      ↓
in-process sensors
      ↓
assessment
```

`dumpcap` captures packets. `tshark` decodes an existing PCAP. Sensors do not invoke external tools.

A single capture is not decoded with a separate tshark process for every protocol. This matters on small appliances and ARM64 hardware.

Sensor results distinguish `absent`, `detected`, `partial`, and `error`. A parser or tool failure is never converted into “protocol absent”.

## Jobs and worker

Long-running operations are durable jobs rather than work performed inside an HTTP request.

Main state transitions:

```text
queued → running → completed
   │        ├────→ failed
   │        ├────→ cancelled
   │        └────→ interrupted
   └─────────────→ cancelled
```

`JobService` owns state transitions. The worker atomically claims queued jobs and dispatches them through the handler registry.

Resource locks live in SQLite. Passive capture and active discovery, for example, cannot use the same `interface:<name>` resource concurrently.

After a worker restart, previously running jobs become `interrupted` with `application_restart`; queued jobs remain queued. Arbitrary scanner processes are not automatically resumed or retried.

## Persistence

SQLite is the local system of record, accessed through SQLAlchemy 2 and Alembic.

Application connections use:

- foreign keys;
- WAL;
- a busy timeout;
- short transactions;
- `synchronous=FULL` by default for appliance deployment.

Scanner or capture execution never runs inside an open SQL transaction.

SQLite stores audits, jobs/events, locks/workers, confirmed scopes, inventory, protocol observations, findings, users/sessions, reports, and evidence metadata.

## Evidence store

Large or raw data is kept outside the main relational rows:

- PCAP;
- Nmap XML;
- raw provider stdout/stderr;
- passive-result JSON;
- generated HTML/JSON reports.

Evidence files are written below a controlled root through a temporary path, flush/fsync, and atomic rename, then registered with SHA-256 metadata in SQLite.

API callers never select filesystem paths.

## Inventory and correlation

`InventoryService` owns assets, addresses, names, services, and evidence provenance.

Identity correlation is conservative: exact MAC first, then exact IP. If MAC identity and IP identity disagree, WireScope records the conflict rather than silently merging assets.

Hostnames from DHCP, PTR, mDNS, LLMNR, NBNS, and Nmap can coexist. A newer source does not erase an older one.

Device and OS classification remain confidence-qualified hints, not confirmed facts.

## Protocol audits

`protocol_audits/` is a registry-driven layer for checking discovered services.

Each module declares:

- a service predicate;
- a required tool;
- a safety class;
- an argv-only command builder;
- a parser;
- timeout/resource limits.

Current providers cover SSH, TLS, HTTP, DNS, SMB, SNMP, and LDAP. They run only for inventory addresses that remain inside confirmed scope.

NSE, brute force, and credential guessing are not part of the default path.

## Findings

The findings engine does not start scanners and does not parse raw stdout.

It consumes normalized observations, inventory, and passive-result artifacts and applies versioned rules. A finding contains severity, confidence, rationale, recommendation, and evidence links.

`suppressed` and `accepted_risk` states survive re-evaluation; state changes are recorded separately.

## Reporting

Report generation also does not contact the network. It builds a versioned `audit-report` view from persisted state and writes self-contained HTML and JSON artifacts.

Raw provider output is referenced through evidence identifiers and hashes rather than copied wholesale into the main report.

## Authentication

Local roles are `auditor` and `viewer`.

A session cookie contains a random token; SQLite stores its SHA-256 digest. Mutating operational routes require `auditor`. Viewers can inspect results but cannot start or cancel work.

Health/readiness and login remain public so the appliance can expose basic state before sign-in.

## Privilege boundary

Production process model:

```text
unprivileged wirescope-api
unprivileged wirescope-worker
          │
          ▼
/usr/bin/dumpcap
root:wireshark 0750
cap_net_admin,cap_net_raw=eip
```

The Python backend does not receive `CAP_NET_RAW` or `CAP_NET_ADMIN`.

Nmap is not elevated automatically. Without raw-socket privileges, the provider uses supported fallbacks and records skipped capabilities.

External tools are executed as argv arrays; `shell=True` is not used.

## Deployment

Both application and appliance installer default to `127.0.0.1:8000`.

That is sufficient for the local kiosk. For LAN operation, the preferred layout is:

```text
browser → HTTPS 443 → Caddy/nginx → 127.0.0.1:8000
```

Direct `0.0.0.0` binding requires an explicit `--bind-host 0.0.0.0` and should be paired with TLS or a deliberate firewall policy.

## Remaining technical debt

Notable remaining items include:

- the frontend still uses compatibility `/api/*` and can migrate to `/api/v1` separately;
- response-generated URLs may still return `/api/*` during that transition;
- PDF export is not implemented;
- there is no dedicated security audit-log table yet;
- there is no policy-driven deletion of completed audits/evidence;
- terminal jobs have no automatic retry;
- tshark compatibility requires release testing against distro package versions.
