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

Environment discovery is separate from passive packet analysis. Interface
allowlisting and scope validation are planned for the passive foundation.

### `engine/passive.py`

Owns the prototype passive pipeline:

1. create a secure temporary pcap;
2. invoke `tshark` for capture;
3. invoke passive sensors over the pcap;
4. aggregate source MAC addresses;
5. build an assessment;
6. remove the pcap in a `finally` block.

The current parser launches many `tshark` subprocesses. This is retained only
for compatibility during Milestone 0 and will be replaced in Milestone 1.

### `sensors/passive.py`

Contains the current protocol-specific extraction functions:

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
- IPv6 Neighbor Solicitation;
- IPv6 Neighbor Advertisement.

The current common shape is `{name, detected, hits, data}`. It does not yet
represent provider errors consistently. Milestone 1 introduces a normalized
Pydantic contract containing errors and evidence references.

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

The current job engine is a process-local dictionary protected by a lock and a
two-thread executor. It is suitable only for the prototype. It has no
persistence, cancellation, cleanup, or multi-process coordination.

### `frontend/`

The current vanilla frontend displays service status and environment details.
It does not yet implement the passive scan workflow. UI expansion follows
backend contracts incrementally and must remain usable at 480×320.

## Current HTTP surface

- `GET /api/status`
- `GET /api/environment`
- `GET /api/passive/{interface}`
- `POST /api/passive/start`
- `GET /api/jobs/{job_id}`
- `GET /api/jobs`
- `GET /`
- `/static/*`

Swagger, ReDoc, and OpenAPI routes are enabled in development and can be
disabled by configuration. The synchronous passive route is legacy prototype
behavior and will be removed after the durable job API is available.

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

- passive parsing still uses repeated `tshark` subprocesses;
- sensor error contracts are inconsistent;
- jobs are not durable;
- API models are mostly implicit dictionaries;
- authentication and authorization are absent;
- interface and scope validation are incomplete;
- frontend supports environment display only;
- no structured logging or audit log exists yet;
- production capture capabilities and systemd units are not configured.

These limitations are scheduled explicitly in
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).
