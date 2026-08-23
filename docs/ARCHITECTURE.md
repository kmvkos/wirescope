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
    │ HTTP
    ▼
backend/app.py
    ├── engine/environment.py
    ├── engine/jobs.py
    └── engine/passive.py
            ├── sensors/passive.py
            └── engine/assessment.py
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
allowlist, and link-state policy. Active scope validation remains Milestone 3.

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

### `engine/jobs.py`

The transitional job engine is a process-local dictionary protected by a lock
and a two-thread executor. It is suitable only for the prototype. It has no
persistence, cancellation, cleanup, or multi-process coordination.

### `frontend/`

The current vanilla frontend displays service status and environment details.
It does not yet implement the passive scan workflow. UI expansion follows
backend contracts incrementally and must remain usable at 480×320.

## Current HTTP surface

- `GET /api/status`
- `GET /api/environment`
- `GET /api/interfaces`
- `POST /api/passive/start` with a JSON request model
- `GET /api/jobs/{job_id}`
- `GET /api/jobs`
- `GET /`
- `/static/*`

Swagger, ReDoc, and OpenAPI routes are enabled in development and can be
disabled by configuration. The blocking synchronous passive route was removed;
the temporary job implementation will be replaced by durable jobs in
Milestone 2.

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
- description;
- evidence references;
- recommendation;
- rule and schema version.

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
are validated before invocation.

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

SQLite will persist audits, jobs, assets, interfaces, observations, services,
findings, evidence, reports, and settings. Schema migrations are mandatory.

A controlled local worker will claim queued jobs from SQLite, update stages and
progress, support cooperative cancellation, and recover interrupted jobs after
restart. The design must ensure that UI or kiosk failure does not terminate an
audit.

## Deployment boundaries

The eventual appliance has separate lifecycle units for:

- WireScope application and worker;
- local kiosk/browser.

The backend binds conservatively by default. Remote access, TLS termination,
and listening interfaces are explicit deployment settings.

## Known transitional debt

- jobs are not durable;
- the process-local job engine does not yet propagate cancellation tokens or
  stage-level progress;
- authentication and authorization are absent;
- active audit scope validation does not exist yet;
- frontend supports environment display only;
- JSON logging exists, but there is no persistent audit log or job/audit
  context propagation;
- retained raw evidence has no durable evidence store or retention policy;
- tshark field compatibility is tested against 4.4 fixtures and still requires
  release testing against the Raspberry Pi OS package version;
- production capability setup, verification tooling, and systemd units are not
  automated yet.

These limitations are scheduled explicitly in
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).
