# WireScope architecture

[Русский](../ARCHITECTURE.md) · **English**

This document describes the architecture as it exists **now**. The historical M0–M8 development path lives in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## System shape

WireScope is a local network-audit appliance. It is designed for one Linux host or VM, so the runtime deliberately avoids Redis, Celery, PostgreSQL, and networked microservices.

```text
browser / local Chromium kiosk
                │
                │ HTTP + session cookie
                ▼
          FastAPI backend
                │
       ┌────────┼─────────────┐
       │        │             │
      auth   audits/jobs   read APIs
                │
                ▼
             SQLite
                ▲
                │
        wirescope-worker
                │
   ┌────────────┼───────────────────────────┐
   │            │           │               │
passive      active      protocol        findings /
capture      discovery    audits          reports
   │            │           │
   ▼            ▼           ▼
dumpcap/      Nmap       ssh-audit, openssl,
tshark                  curl, dig, smbclient,
                         snmpget, ldapsearch
                │
                ▼
          evidence store
```

The project is a **modular monolith**. Module and data-contract boundaries matter; network service boundaries do not.

The API and worker are separate processes over one SQLite database and one managed evidence root. The GUI is a third, independent client: either a normal browser or Chromium running in kiosk mode.

## Architectural rules

Several rules shape most of the codebase:

1. **Observation and interpretation are separate.** Sensors and scanners record facts; assessments and finding rules interpret them.
2. **Long-running work uses durable jobs.** Reloading a page must not terminate Nmap or packet capture.
3. **Scope is validated on the server.** Seeing an address or route is not permission to scan it.
4. **External tools run without a shell.** Commands are argv arrays; `shell=True` is not used on the provider path.
5. **Raw evidence is separate from normalized data.** PCAP, XML, stdout/stderr, and generated reports live as files, not large SQLite BLOBs.
6. **Backend and worker stay unprivileged.** Packet-capture capabilities belong to `dumpcap`, not the Python process.
7. **Tool failure never means protocol absence.** Missing binaries, timeouts, and parser failures remain explicit errors or partial results.
8. **SQLite is intentional.** A single appliance does not need distributed infrastructure to coordinate local work.

## Module boundaries

### `backend/`

`backend/app.py` assembles the FastAPI application, dependencies, authentication guards, and current HTTP routes. The file is still fairly large; the route layer has not yet been split into separate router modules.

The backend:

- validates sessions and roles;
- validates request data;
- creates audits and jobs;
- serves inventory, findings, and reports;
- serves the static frontend;
- exposes health/readiness;
- accesses host network configuration through the controlled `NetworkService` boundary.

The backend does **not** own job lifetime. Once queued, a job exists independently of its originating request and browser tab.

### `config/`

`config/settings.py` is the runtime policy source for paths, capture limits, concurrency, Nmap timeouts, scope caps, provider binaries, cookie settings, TLS, and related configuration.

The application-level default bind is `127.0.0.1:8000`. The appliance installer CLI currently has a separate `--bind-host 0.0.0.0` default, which is why deployment examples set the desired bind explicitly.

### `engine/`

This package contains network and passive-analysis core logic without HTTP concerns.

Important modules:

- `environment.py` — hostname, addresses, routes, DNS, host context;
- `interfaces.py` — interface discovery and interface policy;
- `network.py` / `segment.py` — network context and appliance-mediated network changes;
- `routes.py` — route validation for active targets;
- `scope.py` — canonical target sets, caps, prohibited ranges;
- `active_profiles.py` — Discovery / Standard / Deep profiles;
- `passive.py` — capture/decode/sensor pipeline;
- `assessment.py` — qualified interpretation of passive observations.

### `providers/`

Providers adapt external tools to WireScope's internal contracts.

A provider is responsible for controlled execution and raw/normalized output. It is not responsible for deciding whether an observation is a security finding.

For example, the Nmap provider records hosts/services and stores XML evidence. Finding rules later decide whether any resulting service state is actionable.

### `sensors/` and `parsers/`

`tshark` decodes a PCAP once into line-oriented EK output. The parser normalizes that stream into packet records, and the passive sensors consume those records in-process.

Current passive coverage includes:

- Ethernet/source MAC;
- VLAN/QinQ;
- ARP;
- LLDP/CDP;
- STP;
- DHCPv4/DHCPv6;
- IPv6 RA/NS/NA;
- mDNS/LLMNR/NBNS;
- SSDP.

Sensors do not start additional tshark processes.

### `jobs/`

The job subsystem is WireScope's orchestration layer.

Registered job handlers currently cover:

- `passive_discovery`;
- `packet_capture`;
- `active_discovery`;
- `protocol_audit`;
- `findings_evaluation`;
- `report_generation`.

`JobService` owns audit/job state transitions. `JobWorker` atomically claims queued work and dispatches it through a handler registry.

The worker is not a hard-coded `if/elif` chain keyed on job type; handlers are registered independently.

### `persistence/`

Persistence uses SQLAlchemy 2 and Alembic. Production schema changes are migrations, not `Base.metadata.create_all()`.

SQLite connections use:

- WAL;
- foreign keys;
- configurable busy timeout;
- `synchronous=FULL` by default;
- short transactions.

Scanner execution and packet capture must never happen while holding a database transaction open.

### `storage/`

`EvidenceStore` owns file-backed artifacts.

Files are written through a temporary name, flushed, atomically renamed, hashed with SHA-256, and then registered in SQLite. The database keeps artifact metadata, schema/version information, and an internal relative path.

API callers cannot choose arbitrary evidence filesystem paths.

### `inventory/`

Inventory stores assets, addresses, names, services, and provenance.

Correlation is deterministic:

1. exact MAC match;
2. then exact IP match.

If MAC identity and IP identity disagree, WireScope records the conflict instead of silently merging two assets.

Name provenance is retained. PTR, DHCP, mDNS, LLMNR, NBNS, and Nmap names accumulate rather than overwriting each other as a single authoritative hostname.

### `protocol_audits/`

Protocol audits use a registry of service-aware modules.

Each module declares:

- service predicates;
- required binary;
- safety class;
- argv builder;
- parser;
- timeout;
- normalized observation kinds.

Current modules are SSH, TLS, HTTP, DNS, SMB, SNMP, and LDAP.

A module is dispatched only when an inventory service matches its predicate and the selected asset address is still inside the confirmed scope.

### `findings/`

The rule engine does not start scanners and does not parse raw provider stdout. It reads:

- `protocol_observations`;
- inventory services;
- stored passive-result artifacts.

A finding records rule/version, severity, confidence, affected asset/service, rationale, recommendation, and evidence references.

States are `open`, `suppressed`, and `accepted_risk`; state changes are retained separately.

### `reports/`

Reporting builds the versioned `audit-report` v1 model from persisted data.

Report generation writes HTML and JSON to the evidence store and appends report history. It never re-runs network checks while rendering a report.

### `auth/`

Local users are stored in SQLite.

Roles:

- `auditor` — operational read/write access;
- `viewer` — read-only operational access.

The browser cookie carries a random session token; SQLite stores only its SHA-256 digest. Cookies are HttpOnly and `SameSite=strict`; `Secure` is enabled when direct TLS or a trusted reverse proxy is configured.

### `frontend/`

The frontend remains plain HTML/CSS/JavaScript.

It now handles the audit wizard, job polling, inventory, findings, report preview, network settings, password changes, and listen/record capture. A separate frontend build framework is still not required for runtime.

The compact baseline is a 480×320 kiosk. At 900px and above the layout becomes denser for laptop/desktop use.

### `appliance/` and `packaging/`

These packages turn the Python application into a deployable Linux appliance.

They cover:

- distro and architecture detection;
- apt/dnf/yum/zypper package mapping;
- installer and upgrade flow;
- systemd unit generation;
- dumpcap capability setup and verification;
- kiosk integration;
- backup/restore;
- dependency inventory;
- TLS helper;
- network-control helper;
- checksums and release helpers.

The installer runs from the Git checkout. A system install keeps mutable data under `/var/lib/wirescope` and configuration under `/etc/wirescope`.

## Passive pipeline

```text
validated interface
        ↓
dumpcap: bounded capture
        ↓
temporary PCAP
        ↓
tshark -T ek -l -n
        ↓
line-oriented decode
        ↓
PacketRecord
        ↓
passive sensors
        ↓
SensorResult[]
        ↓
assessment
```

A normal live passive audit therefore uses two subprocesses: one `dumpcap` and one `tshark`. Adding sensors does not add tshark processes.

### `SensorResult`

Each sensor returns:

- `name`;
- `status`;
- `hits`;
- observations;
- summary;
- warnings;
- structured errors;
- compatibility flag `detected`.

Status semantics:

- `absent` — parsing succeeded and no evidence matched;
- `detected` — trustworthy observations were produced;
- `partial` — observations exist, but part of the analysis failed;
- `error` — presence/absence cannot be determined reliably.

A parser error therefore never becomes `absent`.

## Confidence model

Assessments and findings use:

- `confirmed`;
- `high`;
- `medium`;
- `low`;
- `hint`;
- `unknown`.

`confirmed` is deliberately rare. Direct protocol evidence may justify high confidence; device classification from service patterns remains heuristic.

## Active discovery boundary

Active discovery starts from a strict distinction:

```text
observed network data
        ≠
authorized scope
```

Before Nmap runs, the backend:

1. canonicalizes targets using `ipaddress`;
2. enforces target-count limits;
3. rejects unspecified/multicast ranges;
4. validates the interface;
5. resolves routes with `ip route get`;
6. verifies source address and route device;
7. stores an immutable confirmed-scope snapshot;
8. re-validates that snapshot in the worker before provider execution.

See [SCANNING_MODEL.md](SCANNING_MODEL.md).

## Jobs and restart recovery

Job transitions are:

```text
queued  → running
queued  → cancelled
running → completed | failed | cancelled | interrupted
```

Terminal jobs never return to `running`.

If the worker disappears while a job is running, startup recovery changes that job to `interrupted` with `application_restart`. It is not resumed from the middle and is not retried automatically.

Queued jobs survive and remain claimable.

Cancellation of a running job is persisted first. A worker-side monitor then propagates a cooperative cancellation token to the handler and `ToolRunner`, which terminates the child process group.

### Resource locks

Locks live in SQLite, so limits apply across worker threads rather than only inside one Python object.

Examples:

- capture and active discovery use `interface:<name>`;
- global capture/Nmap limits use resource groups;
- protocol audits serialize at audit/group level;
- findings and reports serialize per audit but do not need an interface lock.

Default worker concurrency and the main network job limits are 1, which is intentionally conservative for a small appliance.

## Persistence model

Important tables include:

- `audits`;
- `jobs`;
- `job_events`;
- `artifacts`;
- `resource_locks`;
- `workers`;
- `confirmed_scopes`;
- `assets`, `asset_addresses`, `asset_names`, `services`, `asset_observations`;
- `protocol_observations`;
- `findings`, `finding_state_events`;
- `reports`;
- `users`, `sessions`.

Raw scanner output is not used as a job event log. `job_events` is lifecycle/progress history; stdout/stderr is stored as evidence.

## Privilege boundary

Production should look like this:

```text
wirescope-api        wirescope-worker
   uid=wirescope        uid=wirescope
        │                    │
        └────────┬───────────┘
                 │
                 ▼
             dumpcap
 root:wireshark 0750 + file capabilities
```

Python, Uvicorn, and the worker do not receive `CAP_NET_RAW` or `CAP_NET_ADMIN`.

Nmap follows a separate rule: raw-socket features are used only when those privileges are already available to the process. Otherwise the provider uses TCP connect and records skipped UDP/OS-detection capabilities rather than elevating itself.

User-systemd installs use `sg wireshark` to obtain current group membership. System units use `SupplementaryGroups=wireshark`.

## Kiosk boundary

The kiosk is not part of backend or worker lifetime:

```text
systemd
├── wirescope-api
├── wirescope-worker
└── wirescope-kiosk   (optional)
```

Restarting Chromium does not cancel work. If the kiosk fails, the system can return `getty@tty1` without stopping API or worker.

VMware uses the Xorg/xinit kiosk path. Other hardware can use Cage/Wayland where available, with xinit as a fallback.

## Current technical debt

The current branch still has a few deliberate gaps:

- PDF export is not implemented;
- there is no dedicated security audit-log table;
- policy-driven deletion of completed audits/evidence is not implemented;
- terminal jobs have no manual/automatic retry flow;
- `backend/app.py` remains large and will eventually benefit from splitting the route layer;
- tshark compatibility requires release testing against distro package versions;
- hardware-specific Raspberry Pi kiosk smoke tests remain optional.

These items are tracked in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).
