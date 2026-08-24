# WireScope architecture

## Purpose

WireScope is a portable network discovery, diagnostics, and security audit
appliance. Its production target is Raspberry Pi OS Lite on ARM64, while the
same Python application source must run on Debian AMD64 for development.

WireScope treats command-line tools as evidence providers. Users interact with
the application API and UI, not with raw `tshark`, Nmap, or shell output.

## Architectural principles

1. Sensors and scanners report observations and evidence; assessment and
   finding rules make interpretations.
2. Long-running work is represented by durable, cancellable jobs.
3. Network interfaces and audit scope are validated by the backend.
4. External tools run through one controlled runner without `shell=True`.
5. Raw evidence is retained separately from normalized application data.
6. The backend runs unprivileged. Packet capture privileges belong only to a
   narrowly configured capture provider such as `dumpcap`.
7. SQLite is the appliance-local system of record. Redis, Celery, and other
   distributed infrastructure are not required for a single device.
8. APIs have explicit, versioned Pydantic contracts before UI workflows depend
   on them.
9. Architecture-independent Python is preferred; OS packages must be available
   for both Debian AMD64 and Raspberry Pi OS ARM64.
10. A missing tool or tool failure is an error observation, never equivalent
    to a protocol not being detected.

## Current architecture

The stabilized prototype remains a small modular monolith:

```text
frontend/
    │ HTTP + session cookie
    ▼
backend/app.py
    ├── auth/
    ├── engine/environment.py
    ├── engine/interfaces.py
    ├── engine/scope.py
    ├── engine/routes.py
    ├── jobs/  +  persistence/  +  storage/
    ├── engine/passive.py
    ├── inventory/
    ├── protocol_audits/
    ├── findings/
    └── reports/
```

### `backend/`

`backend/app.py` owns the FastAPI application, static frontend delivery, and
the current HTTP routes. It is intentionally thin but still calls engine
functions directly. API routers and versioned contracts will be introduced as
the API grows.

### `config/`

`config/settings.py` is the central source for application identity and
filesystem paths. Defaults are derived from the source checkout, with
environment overrides for deployment. Production documentation routes can be
disabled with `WIRESCOPE_DOCS_ENABLED`.

### `engine/environment.py`

Discovers local host context through Linux-native sources:

- `ip -j addr`;
- `ip -j route`;
- `/sys/class/net/<interface>/speed`;
- `/etc/resolv.conf`;
- `socket.gethostname()`.

Environment discovery is separate from passive packet analysis. Passive
capture accepts only an exactly discovered interface that passes loopback,
allowlist, and link-state policy. Active discovery additionally requires a
server-validated authorized scope; see [SCANNING_MODEL.md](SCANNING_MODEL.md).

### `engine/passive.py`

Owns the passive pipeline:

1. validate the requested interface against discovered interfaces and policy;
2. ask the capture provider to create one bounded pcap with `dumpcap`;
3. decode that pcap once through line-oriented tshark EK output;
4. normalize packets and run all sensors in process;
5. build evidence-backed assessment conclusions;
6. remove temporary decode and capture files.

The result includes capture/decode subprocess metrics. Normal pcap analysis
uses one subprocess regardless of sensor count; live capture plus analysis uses
two.

### `sensors/passive.py`

Contains independent protocol-specific consumers of normalized packet records:

- Ethernet/source MAC;
- VLAN;
- ARP;
- LLDP;
- CDP;
- STP;
- DHCPv4;
- mDNS;
- LLMNR;
- SSDP;
- IPv6 Router Advertisement;
- IPv6 Neighbor Solicitation and Advertisement;
- DHCPv6;
- NBNS.

Each sensor returns a Pydantic `SensorResult` with status, hit count,
observations, summary, warnings, and errors. Sensors never execute external
tools.

### `engine/assessment.py`

Converts observations into explicitly qualified interpretations:

- traffic visibility;
- trunk-like versus access-or-native port hints;
- tagged VLAN observations;
- LLDP/CDP neighbors;
- IPv4 `/24` grouping hints;
- IPv6 router observations;
- DHCP presence.

The `/24` grouping is a hint and is not treated as a discovered subnet mask.

### `jobs/`, `persistence/`, `storage/`, and `inventory/`

`JobService` is the only domain layer allowed to change audit/job state. It
persists audits, jobs, progress, events, worker heartbeats, and resource locks
through short SQLAlchemy sessions. `JobWorker` claims queued work atomically
and dispatches it through `HandlerRegistry`; handlers never appear in an
`if/elif` chain. `passive_discovery`, `active_discovery`, `protocol_audit`, and
`findings_evaluation`, and `report_generation` are registered handlers.

`EvidenceStore` writes generated files under a controlled root using a
temporary suffix, `fsync`, and atomic replacement. SQLite stores only metadata,
hashes, schema versions, and relative paths. Nmap XML is an artifact file, not
a database BLOB.

`InventoryService` owns confirmed scopes, assets, addresses, names, services,
vendor lookup, and deterministic MAC/IP correlation. Job status never inlines
the inventory; clients use the dedicated inventory endpoints.

`protocol_audits/` is the Milestone 4 plugin package. Each module declares
service predicates, a required tool, safety class, argv-only command builder,
and a parser that emits normalized observations. `ProtocolAuditHandler`
dispatches modules only when inventory services match. Raw tool output is an
evidence artifact; `protocol_observations` rows are bounded JSON facts, not
findings.

`findings/` is the Milestone 5 rule package. Declarative rules consume
`protocol_observations`, inventory services, and stored passive-result
artifacts. `FindingsEvaluationHandler` does not invoke scanners or parse
stdout. Findings persist with severity, confidence, evidence links, and a
suppress/accepted-risk audit trail.

`reports/` is the Milestone 6 reporting package. It builds a versioned
`audit-report` view from persisted audits, inventory, findings, environment
snapshots, and artifact metadata. HTML and JSON are written through the
evidence store. Raw provider output is referenced by id and hash only.

`auth/` is the Milestone 7 local identity package. Users have role
`auditor` or `viewer`. Sessions are random tokens stored as SHA-256
digests. The API requires a session for operational routes; viewers may
read but cannot start or cancel work.

### `frontend/`

The vanilla operator GUI implements the audit wizard and result screens at a
480×320 kiosk baseline, with a denser laptop layout above 900px. It polls
durable jobs and never cancels work on display restart. See
[GUI_MODEL.md](GUI_MODEL.md).

## Current HTTP surface

- `GET /api/status`
- `GET /api/health`
- `GET /api/ready`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/environment`
- `GET /api/interfaces`
- `POST /api/audits`
- `GET /api/audits`
- `GET /api/audits/{audit_id}`
- `POST /api/audits/{audit_id}/passive`
- `POST /api/audits/{audit_id}/discovery`
- `POST /api/audits/{audit_id}/protocol-audits`
- `GET /api/audits/{audit_id}/assets`
- `GET /api/audits/{audit_id}/assets/{asset_id}`
- `GET /api/audits/{audit_id}/services`
- `GET /api/audits/{audit_id}/inventory`
- `GET /api/audits/{audit_id}/observations`
- `POST /api/audits/{audit_id}/findings`
- `GET /api/audits/{audit_id}/findings`
- `GET /api/audits/{audit_id}/findings/{finding_id}`
- `POST /api/audits/{audit_id}/findings/{finding_id}/suppress`
- `POST /api/audits/{audit_id}/findings/{finding_id}/accept-risk`
- `POST /api/audits/{audit_id}/findings/{finding_id}/reopen`
- `POST /api/audits/{audit_id}/reports`
- `GET /api/audits/{audit_id}/reports`
- `GET /api/audits/{audit_id}/reports/{report_id}`
- `GET /api/audits/{audit_id}/reports/{report_id}/export`
- `GET /api/audits/{audit_id}/jobs`
- `GET /api/jobs/{job_id}`
- `GET /api/jobs`
- `POST /api/jobs/{job_id}/cancel`
- `GET /api/jobs/{job_id}/events`
- `GET /api/jobs/{job_id}/result`
- `GET /`
- `/static/*`

Swagger, ReDoc, and OpenAPI routes are enabled in development and can be
disabled by configuration. Audit and job list endpoints are paginated. Job
status does not inline potentially large result documents.

## Target logical architecture

```text
WireScope UI
    │
    ▼
Versioned Application API ───────── Authentication / authorization
    │
    ├── Environment service
    ├── Audit service
    ├── Job service
    └── Report service
            │
            ▼
Audit orchestrator
    ├── Passive capture and sensors
    ├── Active discovery scanners
    └── Service-aware audit providers
            │
            ▼
Normalized observations and evidence
            │
            ├── Assessment engine
            └── Findings engine
                    │
                    ▼
                  SQLite
                    │
              Reports and UI
```

The target remains a modular monolith. Boundaries are Python modules and data
contracts, not networked microservices.

## Planned core contracts

### Observation

An observation records a fact produced by a sensor or scanner:

- stable type and schema version;
- audit and asset context;
- provider and tool version;
- normalized data;
- timestamp;
- evidence references;
- warnings and errors.

### Assessment

An assessment records an interpretation:

- statement;
- confidence (`confirmed`, `high`, `medium`, `low`, `hint`, `unknown`);
- supporting observation references;
- limitations and rationale.

### Finding

A finding records an actionable security or diagnostic result:

- title and rule identifier;
- severity (`critical`, `high`, `medium`, `low`, `info`);
- affected asset and service;
- description, rationale, and recommendation;
- observation and evidence references;
- rule and schema version;
- status (`open`, `suppressed`, `accepted_risk`) with an audit trail.

See [FINDINGS_MODEL.md](FINDINGS_MODEL.md).

### Report

A report is a versioned export of persisted audit data:

- schema `audit-report` version 1;
- executive summary, environment, scope, assets, services, findings,
  recommendations, evidence references, and audit metadata;
- HTML and JSON artifacts stored under the evidence root;
- generation history with a content `source_hash`.

See [REPORTING_MODEL.md](REPORTING_MODEL.md).

### Tool result

Every external tool invocation produces:

- executable and sanitized argument list;
- start time and duration;
- exit code;
- stdout/stderr evidence references;
- tool version;
- timeout and cancellation state;
- normalized error category.

## Passive pipeline

Milestone 1 uses a fixed two-process budget for a normal live scan:

```text
validated interface
    ↓
dumpcap capture once → bounded temporary pcap
    ↓
tshark -T ek -l -n decode once → line-oriented structured output
    ↓
normalized PacketRecord collection
    ↓
independent in-process sensors
    ↓
assessment with explicit confidence and evidence references
```

`dumpcap` is responsible only for capture. `tshark` is responsible only for
decoding an existing pcap. Sensors never invoke either tool. A pcap-only
analysis therefore uses one subprocess; a live capture plus analysis uses two.
Tool-version discovery may be cached outside the per-scan budget.

EK was selected because it is line-oriented and can be written to a bounded
temporary decode file instead of materializing a large JSON array in memory.
The parser reads that file incrementally and normalizes field names while
retaining raw field values for protocol-specific sensors. Capture duration,
packet count, pcap size, and command output are bounded for Raspberry Pi.

Supplemental decode passes are not part of the default design. If a required
field cannot be represented by EK, an exception must be benchmarked,
documented, and instrumented rather than added inside an individual sensor.

### Sensor result contract

Every registered sensor produces `SensorResult`:

- `name`;
- `status`;
- `hits`;
- typed observation envelopes containing protocol-specific data;
- aggregate `summary`;
- `warnings`;
- structured `errors`;
- computed `detected` compatibility flag.

Status semantics:

- `absent` — parsing succeeded and no matching protocol evidence was present;
- `detected` — one or more trustworthy observations were produced;
- `partial` — observations were produced, but parser/sensor errors mean the
  result may be incomplete;
- `error` — the sensor could not make a trustworthy presence/absence
  determination.

An errored parser therefore makes a sensor `error` or `partial`, never
`absent`.

### Observation and evidence model

An observation is a fact with:

- sensor and fact kind;
- timestamp;
- source/destination MAC and IP where available;
- protocol;
- packet evidence reference and frame number;
- protocol-specific data.

Protocol-specific structures remain nested. DHCP options, LLDP neighbors, IPv6
prefixes, and naming records are not forced into one lossy flat schema.

### Error model

Tool errors retain exit code and stderr. The common runner distinguishes:

- missing binary;
- permission denied;
- timeout;
- cancellation;
- non-zero exit;
- process/output startup failure.

Pipeline errors distinguish interface, capture, decode, malformed input,
sensor, cancellation, and cleanup failures. Raw stderr is evidence detail and
is not converted into `detected=false`.

### Confidence model

- `confirmed` — directly and independently verified fact; passive assessments
  use this sparingly because they do not actively verify configuration.
- `high` — explicit protocol configuration or direct advertisement, such as a
  DHCP mask/router option or LLDP neighbor.
- `medium` — multiple direct observations support an interpretation, such as
  multiple tagged VLANs suggesting trunk-like behavior.
- `low` — limited direct evidence supports more than one interpretation.
- `hint` — useful grouping or weak inference, such as ARP addresses grouped by
  the first 24 bits.
- `unknown` — evidence is absent, failed, or insufficient.

Assessment conclusions include rationale, source references, and limitations.
Facts remain in sensor observations and are not duplicated as conclusions.

## Privilege model

Production must use:

```text
unprivileged WireScope API/worker
    │
    ▼
dumpcap with Wireshark group/capabilities
    │
    ▼
controlled capture path
```

The Python backend must not run as root and must not receive broad network
capabilities. Capture arguments, interface names, durations, and output paths
are validated before invocation. Active discovery uses Nmap only after scope
and route validation. If `CAP_NET_RAW` is absent, the Nmap provider falls back
to TCP connect scans and skips ARP, UDP, and OS detection instead of
elevating the backend. Protocol audits run unprivileged against confirmed
inventory addresses only and never raise process capabilities.

The verified Debian development configuration is:

- `/usr/bin/dumpcap` owned by `root:wireshark`, mode `0750`, not setuid;
- file capabilities `cap_net_admin,cap_net_raw=eip`;
- `wirescope` is a member of `wireshark`;
- bounded capture as `wirescope` succeeds without root.

Normal capture disables promiscuous mode by default (`dumpcap -p`), uses a
65,535-byte snap length, and enforces independent duration, packet-count, and
file-size limits. Capture directories are `0700`; decode output is `0600`.
Dropped packet counters produce warnings even when dumpcap exits successfully.

## Persistence and jobs

Milestone 2 uses SQLite through SQLAlchemy 2 and Alembic. Production schema is
created only through migrations, not `Base.metadata.create_all()`.

Current tables:

- `audits` — session scope, profile, lifecycle, environment reference, summary;
- `jobs` — universal task state, monotonic progress, parameters, typed error,
  result reference, cancellation, attempt, and resource requirements;
- `job_events` — bounded lifecycle/progress history, not scanner stdout;
- `artifacts` — relative path, content type, size, SHA-256, retention and
  result-schema metadata;
- `resource_locks` — durable exclusive-resource ownership;
- `workers` — process/thread heartbeat and readiness state;
- `confirmed_scopes` — immutable authorized active-scan snapshots;
- `assets`, `asset_addresses`, `asset_names`, `services`,
  `asset_observations` — inventory with provenance;
- `protocol_observations` — idempotent protocol facts with confidence,
  bounded JSON data, and evidence artifact references;
- `findings` — versioned rule results with severity, confidence, status,
  observation and evidence links;
- `finding_state_events` — suppress / accepted-risk / reopen audit trail;
- `reports` — generated report history, source hash, and HTML/JSON artifact
  references;
- `users` — local operator accounts and roles;
- `sessions` — hashed session tokens and expiry.

SQLite connections enable WAL, foreign keys, a configurable busy timeout, and
`synchronous=FULL` by default for appliance power-loss durability. Scanner work
never runs inside a database transaction.
Atomic claiming and restart recovery use short `BEGIN IMMEDIATE`
transactions.

### Process model

Production runs two processes over one SQLite database:

```text
wirescope-api                       wirescope-worker
     │                                    │
     └──────────── SQLite WAL ────────────┘
                       │
                controlled evidence root
```

The API creates metadata and never owns execution lifetime. The worker process
starts a configurable bounded thread pool (default one), claims queued jobs,
and invokes registered handlers. This keeps SQLite and appliance operation
simple while preserving a future process split. The kiosk remains a third,
independent process.

Only one healthy worker supervisor process may hold the supervisor lease.
Configured concurrency is therefore not multiplied accidentally by launching
another worker command.

### State and recovery semantics

Job transitions:

```text
queued  → running
queued  → cancelled
running → completed | failed | cancelled | interrupted
```

Terminal jobs are immutable. There are no automatic retries; the typed error
records whether a later explicit retry may be reasonable.

On worker startup, jobs left `running` by a previous worker become
`interrupted` with code `application_restart`. Their locks are released.
Queued jobs remain queued and can be claimed normally. Arbitrary scanner jobs
are never resumed automatically.

Queued cancellation is immediate. Running cancellation sets a persistent
request; a worker-side monitor sets the Milestone 1 cancellation token, which
terminates the active subprocess group cooperatively. Cancellation ends as
`cancelled`, not `failed`.

Passive jobs request both `interface:<name>` and the `packet_capture` resource
group. Locks live in SQLite, so two worker threads cannot capture the same
interface and the configured global capture limit is enforced.

### Artifact durability and cleanup

Artifact paths are generated from internal UUIDs; API callers cannot supply
filesystem paths. Result JSON is versioned (`passive-result`, schema version
1). A file is written as `*.tmp-<uuid>`, flushed, atomically renamed, hashed,
then registered in SQLite. Power loss before metadata commit can leave only an
orphan final file, which startup maintenance removes only after the configured
stale-file age to avoid racing a concurrent metadata commit. Partial temporary
files and stale managed capture directories are also cleaned conservatively.

Raw PCAP retention is disabled by default. When enabled, a completed capture is
imported into evidence storage and the runtime capture directory is force
cleaned. Audit records and registered evidence are never deleted without an
explicit retention policy.

### Persistence baseline

The lightweight benchmark on the Debian AMD64 development host (50 jobs,
2 KiB result documents) measured:

- initial migration: about 20 ms;
- persistence object startup: under 1 ms;
- job insertion median: about 0.9 ms;
- progress/event update median: about 0.8 ms;
- atomic result persistence median: about 0.6 ms;
- completion/event update median: about 1.4 ms;
- listing 50 jobs: about 2.8 ms.

These numbers are regression indicators, not Raspberry Pi guarantees. The
design performs commits per meaningful stage/event and result, never per
captured frame.

## Deployment boundaries

The appliance process boundary is:

- WireScope API;
- WireScope worker;
- local kiosk/browser.

The backend binds conservatively by default. Remote access, TLS termination,
and listening interfaces are explicit deployment settings.

## Known transitional debt

- PDF export is still unavailable (`422 pdf_not_available`);
- structured logs include audit/job context in the worker, but there is no
  separate security audit-log table yet;
- retention cleanup is conservative and does not yet delete completed audits
  or registered evidence automatically;
- terminal-job retry records and a manual retry API are not implemented;
- SQLite backup/export and corruption-recovery operator tooling remain future
  appliance work;
- tshark field compatibility is tested against 4.4 fixtures and still requires
  release testing against the Raspberry Pi OS package version;
- production capability setup, verification tooling, and systemd units are not
  automated yet.

These limitations are scheduled explicitly in
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).
