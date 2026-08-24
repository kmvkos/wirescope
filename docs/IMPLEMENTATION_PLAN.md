# WireScope implementation plan

## Planning rules

This plan converts the prototype into a portable appliance through reviewable
milestones. A milestone is complete only when its acceptance criteria pass.
Later milestones may refine earlier contracts through migrations, but they
must not bypass the boundaries in `ARCHITECTURE.md`.

Cross-cutting rules:

- support Python 3.11+ on generic Linux (Debian/Ubuntu and RPM families) for
  amd64 and arm64;
- do not run the backend as root;
- do not use `shell=True`;
- validate interfaces, scope, addresses, ports, paths, and profiles;
- persist raw evidence separately from normalized data;
- preserve tool errors explicitly;
- keep live-network tests opt-in;
- add a fixture and unit test for every parser/provider;
- update architecture and operational documentation with each milestone.

## Dependency graph

```text
M0 Stabilize
    ↓
M1 Passive foundation
    ↓
M2 Persistence + jobs + auth foundation
    ↓
M3 Active discovery
    ↓
M4 Service-aware protocol audits
    ↓
M5 Findings
    ↓
M6 Reporting
    ↓
M7 Full GUI
    ↓
M8 Linux appliance
```

M5 rule development can begin against fixtures after M3 contracts stabilize.
M6 JSON report schemas can begin with M5. Full GUI work depends on stable API
contracts but minimal UI integration is required throughout.

---

## Milestone 0 — Stabilize

### Objectives

Create a reproducible, importable, documented baseline without redesigning the
passive pipeline prematurely.

### Tasks

- initialize Git and record the original prototype;
- ignore virtual environments, pcaps, databases, logs, secrets, and generated
  reports;
- fix syntax and import failures;
- remove confirmed dead duplicate parser functions;
- remove duplicate imports;
- centralize project, frontend, and data paths;
- make development documentation routes configurable;
- add `pyproject.toml` with runtime and development dependencies;
- add tests for API smoke behavior, settings, environment normalization,
  sensors, and assessment;
- document current and target architecture;
- record the complete milestone roadmap.

### Acceptance criteria

- `import backend.app` succeeds;
- tests run without live packet capture;
- all tests pass on the development host;
- no application path is hardcoded to `/opt/wirescope`;
- baseline and stabilization changes exist as separate commits;
- known transitional debt is documented.

---

## Milestone 1 — Passive foundation

Status: implemented on `milestone-1-passive-foundation`.

### 1. External tool runner

Create a shared `providers/tools` layer before changing sensors.

Tasks:

- define Pydantic models for command specification and tool result;
- execute argument arrays only, never shell strings;
- capture exit code, duration, stdout, stderr, timeout, cancellation, and tool
  version;
- classify missing binary, permission denied, timeout, non-zero exit, invalid
  output, and cancellation;
- support bounded output and evidence-file streaming;
- redact sensitive arguments in logs;
- terminate subprocess groups during cancellation;
- add fake-runner unit tests for every failure category.

Dependencies: none beyond M0.

### 2. Environment and interface policy

- normalize interface models with Pydantic;
- discover interfaces from `iproute2` and `/sys`;
- add optional `ethtool` data;
- resolve DNS through `resolv.conf` and systemd-resolved when available;
- implement interface allowlist settings;
- reject nonexistent, loopback, virtual, or policy-denied interfaces unless
  explicitly permitted;
- expose an API that returns usable interfaces and denial reasons;
- add sanitized iproute2 fixtures and validation tests.

Dependencies: tool runner.

### 3. Capture provider and privilege boundary

- use `dumpcap` for capture and `tshark` for decoding;
- validate interface and duration before execution;
- define maximum capture size and duration;
- write captures to a controlled per-audit directory with restrictive modes;
- record capture metadata and errors;
- document Wireshark group/capability setup;
- verify the API runs unprivileged;
- add an opt-in integration test for real capture permissions.

Dependencies: tool runner, interface policy.

### 4. Efficient pcap decoding

Adopt a streaming structured-output decoder:

```text
pcap
  → one tshark EK/JSON stream for selected protocol layers
  → normalized packet events
  → sensor consumers
```

Tasks:

- create pcap parser and normalized packet/event types;
- parse one structured tshark stream incrementally;
- allow at most a small documented number of supplemental passes for fields
  unavailable from the main stream;
- benchmark CPU, memory, elapsed time, and subprocess count on Raspberry Pi
  representative fixtures;
- reject corrupt pcaps and unknown fields as explicit parser errors;
- preserve raw decode evidence separately;
- add DHCP, LLDP, VLAN, IPv6 RA, and mixed-traffic pcap fixtures.

Decision gate: retain tshark structured output unless benchmarks demonstrate
that a Python packet library materially reduces complexity and resource use.

Dependencies: tool runner, capture metadata model.

### 5. Sensor contracts and registry

Create stable models:

- sensor name and schema version;
- `detected`;
- hit count;
- typed normalized data;
- evidence references;
- warnings;
- errors;
- provider/tool metadata.

Add a registry so sensors can be enabled by profile without modifying the core
orchestrator.

Implement or expand:

- Ethernet/MAC;
- VLAN 802.1Q and QinQ observations;
- ARP;
- DHCPv4;
- LLDP;
- CDP;
- STP/RSTP;
- IPv6 RA;
- IPv6 NS/NA;
- DHCPv6;
- mDNS;
- LLMNR;
- NBNS;
- SSDP.

Tool/parser errors must result in an errored sensor result, not
`detected=false`.

Dependencies: normalized packet events.

### 6. Assessment v2

- introduce confidence enum: `confirmed`, `high`, `medium`, `low`, `hint`,
  `unknown`;
- require supporting observation references and rationale;
- distinguish untagged traffic, tagged VLANs, multiple VLANs, possible native
  VLAN, access-like, and trunk-like observations;
- prohibit claims that an unseen VLAN does not exist;
- preserve subnet-mask uncertainty for ARP-derived IPv4 groups;
- assess DHCP, neighbors, STP root, IPv6 routers, naming protocols, and traffic
  visibility without duplicating sensor parsing;
- add table-driven tests for confidence and non-overclaiming.

Dependencies: sensor contracts.

### 7. Passive API

- replace the synchronous scan endpoint with a job-oriented contract;
- add request/response Pydantic models;
- expose capture stage, sensor progress, warnings, and errors;

The existing process-local job adapter remains until Milestone 2. Minimal UI
integration is deferred until durable job status/stage contracts exist, rather
than coupling the UI to a transitional queue.

### Milestone 1 acceptance criteria

- one capture produces all passive sensor results;
- normal analysis uses one structured decode stream and no undocumented
  repeated tshark loops;
- every sensor has errors and evidence in its contract;
- invalid interfaces are rejected before capture;
- backend runs unprivileged with documented dumpcap permissions;
- fixture-based tests cover all required passive protocols;
- malformed input, missing tools, permission failures, and protocol absence
  remain distinguishable.

Implementation evidence:

- generated sanitized pcap fixtures cover VLAN/QinQ, ARP, DHCPv4, LLDP, CDP,
  STP, IPv6 RA/ND, DHCPv6, mDNS, and SSDP;
- normalized packet fixtures cover multiple VLANs, multiple DHCP servers,
  multiple IPv6 routers, LLMNR, and NBNS;
- pcap-only analysis reports one tshark subprocess for all fourteen sensors;
- live capture is bounded to one dumpcap process plus one tshark decode;
- the Debian development host verified bounded dumpcap capture as the
  unprivileged `wirescope` user.

Deferred refinements:

- optional ethtool/systemd-resolved environment enrichment;
- cached provider version inventory;
- durable evidence storage and retention;
- UI progress workflow, which depends on Milestone 2 durable jobs.

---

## Milestone 2 — Jobs, persistence, and audit sessions

Status: implemented on `milestone-2-jobs-persistence`.

### Persistence

Use SQLite with SQLAlchemy 2 and Alembic. This adds modest local dependencies
but provides explicit transactions, relationships, and durable migrations for
the growing schema.

Milestone 2 intentionally creates only:

- audit sessions;
- universal jobs;
- job events;
- evidence/artifact metadata;
- durable resource locks;
- worker heartbeat/lease records.

Passive results remain versioned JSON artifacts. Asset, service, observation,
finding, report, user, and role normalization remains deferred.

Operational requirements:

- enable foreign keys;
- use WAL mode where appropriate;
- avoid storing large raw evidence blobs in frequently queried tables;
- test forward migration from every released schema.

### Durable local worker

- implement a controlled worker that claims jobs transactionally from SQLite;
- states: queued, running, completed, failed, cancelled, interrupted;
- stages and monotonic progress;
- cooperative cancellation plus subprocess termination;
- startup recovery for interrupted jobs;
- retention and cleanup policy;
- per-interface capture lock;
- configurable global and per-provider concurrency;
- result and evidence references instead of large list payloads;
- separate worker lifecycle from kiosk lifecycle.

No Redis or Celery.

### Audit/session workflow

- create audit;
- snapshot environment and selected interface;
- store user-confirmed scope, VLAN, and profile;
- enqueue passive and later active stages;
- expose audit history and job event polling.

### Acceptance criteria

- jobs and audits survive backend restart;
- cancellation stops child processes;
- two workers cannot claim the same job;
- concurrent capture on one interface is prevented;
- migrations build a new database and upgrade the previous schema;
- progress, events, typed errors, and result references persist;
- result artifacts are atomic, hashed, and stored outside SQLite;
- audit/job lists are paginated;
- passive fixture integration survives reconstruction of application objects.

Implementation evidence:

- one Alembic revision creates the full Milestone 2 schema from an empty DB;
- SQLite uses WAL, foreign keys, busy timeout, and short transactions;
- production process model separates `wirescope-api` and
  `wirescope-worker`;
- worker startup interrupts abandoned running jobs and retains queued jobs;
- persistent interface and capture-group locks serialize passive capture;
- cooperative cancellation reaches `ToolRunner`;
- startup maintenance removes stale temporary captures, temporary artifact
  files, and unregistered orphan files;
- the offline passive integration test persists progress, result, assessment,
  and environment references across object restart.

Deferred operational work:

- automated SQLite backup/export and corruption-recovery tooling;
- explicit manual retry endpoint;
- policy-driven deletion of completed audits and registered evidence;
- authentication and authorization before remote active-scanning exposure.

---

## Milestone 3 — Active discovery

Status: implemented on `milestone-3-active-discovery`. See
[SCANNING_MODEL.md](SCANNING_MODEL.md).

### Scope model

- represent IPv4/IPv6 hosts and CIDRs with `ipaddress`;
- distinguish observed network hints from authorized audit scope;
- require confirmation before Nmap runs;
- enforce configurable per-profile address caps;
- reject unspecified/multicast targets including `0.0.0.0/0` and `::/0`;
- store an immutable confirmed-scope snapshot with interface, profile, route
  context, and timing policy.

### Nmap provider

- detect version and `CAP_NET_RAW` without raising backend privileges;
- generate argument arrays from Discovery/Standard/Deep profiles;
- prefer XML output for stable parsing;
- store raw XML as evidence;
- normalize hosts, addresses, MAC/vendor, ports, protocols, states, services,
  versions, and OS hints;
- distinguish provider failure from zero discovered hosts;
- support cancellation and timeouts;
- never enable NSE/`-sC`/vulnerability scripts.

### Asset and service inventory

- correlate passive MAC/IP observations with active hosts using exact MAC then
  exact IP;
- keep hostname provenance (PTR, DHCP, mDNS, LLMNR, NBNS, Nmap);
- upsert services by asset, protocol, and port;
- preserve conflicting evidence rather than silently merging identities.

### Acceptance criteria

- Nmap XML fixtures parse without Nmap installed;
- live integration tests are opt-in (`pytest -m network`);
- generated commands cannot escape confirmed scope;
- assets and services persist with evidence provenance;
- inventory listing is paginated and filtered independently of job status.

---

## Milestone 4 — Service-aware protocol audits

Status: implemented on `milestone-4-protocol-audits`. See
[SCANNING_MODEL.md](SCANNING_MODEL.md#protocol-audits).

Create a provider/plugin interface with:

- supported service predicates;
- required tool and minimum version;
- safety classification (`safe` / `gated` / `never-default`);
- command builder (argv arrays only);
- parser independent of persistence;
- normalized observations with confidence;
- timeout and resource budget;
- fixture tests.

Initial modules:

1. SSH: `ssh-audit` non-intrusive fingerprinting. No brute force.
2. TLS: OpenSSL `s_client` handshake and certificate metadata.
3. HTTP: curl headers/status/title. Nikto and Nuclei are gated off.
4. SMB: unauthenticated `smbclient -N -L` null-session probe only.
5. DNS: in-scope `dig` CHAOS identity and flag observations.
6. SNMP: SNMPv3 noAuth probe only; no community guessing or walks.
7. LDAP: anonymous `ldapsearch` base DSE only.

NSE is not used. Optional tools (`testssl.sh`, Nikto, Nuclei) are registered
as `never-default` stubs and cannot be dispatched.

The orchestrator dispatches a module only when normalized service evidence
matches it. Each optional tool reports availability without preventing the
rest of the audit.

Later providers can cover FTP, SMTP, RDP, Redis, PostgreSQL, MySQL/MariaDB,
MSSQL, MongoDB, Elasticsearch, MQTT, UPnP, IPMI, NTP, TFTP, Telnet, VNC,
Docker API, and Kubernetes API.

Acceptance criteria:

- adding a provider does not modify core orchestration;
- every provider has fixtures for success, absence, timeout, and malformed
  output;
- destructive/brute-force/fuzzing actions are not present in default profiles.

---

## Milestone 5 — Findings engine

Status: implemented on `milestone-5-findings-engine`. See
[FINDINGS_MODEL.md](FINDINGS_MODEL.md).

- define versioned finding and severity models;
- create declarative rules independent of scanners;
- correlate multiple observations and evidence sources;
- deduplicate findings across providers;
- record rule version, rationale, evidence, asset, service, recommendation,
  and confidence;
- support suppressed/accepted-risk state with audit trail;
- add tests for severity, correlation, deduplication, and false-positive
  boundaries.

Initial rule families:

- exposed insecure management protocols;
- weak SSH algorithms;
- TLS protocol/cipher/certificate issues;
- SMB signing and legacy dialect findings;
- DNS recursion/configuration observations;
- SNMP exposure;
- HTTP security configuration;
- infrastructure anomalies from passive assessment.

Acceptance criteria:

- findings never depend on parsing raw stdout directly;
- every finding links to normalized observations and raw evidence;
- rules produce deterministic results from fixtures.

Implementation evidence:

- Alembic revision `f5a91c3e7b04` adds `findings` and `finding_state_events`;
- `findings/rules/` is a registry of declarative rules over
  `protocol_observations`, inventory services, and stored passive-result
  artifacts;
- job type `findings_evaluation` takes `audit:<id>` plus group `findings`
  (max 1) and does not take `interface:<name>` or invoke scanners;
- API lists, gets, suppresses, accepts risk, and reopens findings;
- default pytest stays fixture-based (`-m not network`).

---

## Milestone 6 — Reporting

Status: implemented on `milestone-6-reporting`. See
[REPORTING_MODEL.md](REPORTING_MODEL.md).

- define a versioned report view model;
- generate self-contained HTML;
- generate normalized JSON export;
- retain report history and generation metadata;
- organize executive summary, environment, scope, assets, services, findings,
  recommendations, evidence references, and audit metadata;
- keep raw provider output outside the primary human report;
- sanitize rendered evidence against HTML injection;
- add snapshot and schema tests;
- evaluate PDF only after HTML stabilizes.

Acceptance criteria:

- reports reproduce from persisted audit data;
- HTML is readable on laptop and local display;
- JSON validates against the published schema;
- exports cannot read or write outside controlled paths.

Implementation evidence:

- Alembic revision `a6c14f8d9e20` adds `reports` history;
- `reports/` builds schema `audit-report` v1 from persisted audits, inventory,
  findings, environment snapshots, and artifact metadata;
- published schema lives at `reports/schema/audit-report-v1.json`;
- job type `report_generation` takes `audit:<id>` plus group `report`
  (max 1) and does not take `interface:<name>` or invoke scanners;
- API lists report history and exports HTML/JSON through the evidence store;
- PDF remains unavailable (`422 pdf_not_available`);
- default pytest stays fixture-based (`pytest -m not network`).

---

## Milestone 7 — Full GUI

Status: implemented on `milestone-7-gui`. See [GUI_MODEL.md](GUI_MODEL.md).

Implement the workflow:

```text
login
→ new audit
→ environment
→ interface
→ network/VLAN/scope
→ profile
→ confirmation
→ progress
→ summary
→ assets/findings
→ report
```

Tasks:

- role-aware login and session handling;
- touch targets and layouts tested at 480×320;
- resilient polling or server events for progress;
- explicit stop/cancel behavior;
- clear separation of observations, assessments, and findings;
- detailed laptop layout without making the kiosk unusable;
- accessible status, errors, and confirmation dialogs;
- browser tests for the complete audit workflow.

Acceptance criteria:

- an auditor completes an audit without shell access;
- viewer cannot start or cancel audits;
- kiosk recovery does not affect a running backend job.

Implementation evidence:

- Alembic revision `b7d25e9a1c31` adds `users` and `sessions`;
- roles are `auditor` and `viewer`; sessions are HttpOnly cookies with
  hashed tokens;
- vanilla frontend wizard covers login through report at a 480×320 kiosk
  baseline, with a denser laptop layout above 900px;
- the UI polls jobs with backoff and never cancels on display reload;
- viewers receive `403 forbidden_role` on mutating routes;
- default pytest stays fixture-based (`pytest -m not network`); Playwright
  kiosk-viewport tests skip when Chromium is unavailable.

---

## Milestone 8 — Generic Linux appliance

Primary target: unprivileged API + worker + browser GUI on a common Linux
server or VM. Raspberry Pi kiosk hardware is a later extra, not a gate.

### Installer

- detect OS family through `apt`, `dnf`, `yum`, or `zypper`, and `amd64`
  versus `arm64`, without requiring Raspberry Pi;
- install dumpcap/tshark/nmap via distro package names (they differ);
- create an unprivileged service account and controlled directories;
- configure dumpcap file capabilities (`setcap`) without backend-as-root;
- support `--user-install` and root systemd units when sudo works;
- bind host is configurable (`127.0.0.1` or `0.0.0.0` for VM/LAN);
- install pinned Python dependencies;
- initialize and migrate SQLite;
- create initial admin securely;
- support idempotent upgrade and rollback guidance.

### systemd

- application/API unit;
- worker unit;
- `SupplementaryGroups=wireshark` on system units; `sg wireshark` on user
  units so dumpcap works without a new login;
- optional kiosk unit kept as a later extra, not enabled by default;
- dependency ordering and health checks;
- controlled restart limits;
- log retention;
- no secrets embedded in unit files.

### Optional later extra (Raspberry Pi / local display)

Chromium kiosk, 480×320, Pi OS Lite, and touch validation are **not**
acceptance criteria. Keep `packaging/kiosk/` labeled as optional. Opt-in
`pytest -m live_pi` stays unused.

### Security and release

- production docs disabled or access-controlled;
- conservative bind address and firewall guidance for loopback or LAN;
- dependency and OS-package inventory per family;
- backup/restore procedure;
- signed release artifacts or checksums;
- fixture tests including distro-detection fixtures;
- complete `INSTALLATION.md`, `SECURITY_MODEL.md`, and operational runbook.

Acceptance criteria:

- a clean generic Linux install (Debian/Ubuntu, and at least one RPM family
  in fixtures) reaches the WireScope login screen in a local or LAN browser;
- backend and capture run with documented least privilege;
- reboot during a queued/running audit has defined recovery behavior;
- default tests pass with `pytest -m not network` (`live_pi` unused).

Debian AMD64 VM is the first verification gate. Fedora/RHEL/openSUSE package
names and package-manager detection are covered by fixtures. Raspberry Pi OS
Lite HDMI kiosk remains an optional later extra of the same installer.

---

## Deferred decisions and evaluation gates

- **Tshark structured format:** choose EK versus JSON after fixture benchmarks.
- **Frontend framework:** retain vanilla UI until workflow complexity justifies
  a framework; select based on bundle size, maintenance, and kiosk performance.
- **PDF engine:** defer until HTML report requirements stabilize.
- **Optional scanners:** package and enable independently; absence must degrade
  capability, not application health.
- **Remote transport security:** reverse proxy in front of loopback is the
  preferred LAN path; optional direct TLS on uvicorn is documented. Do not
  expose unprivileged HTTP on `0.0.0.0` without a firewall.

## Definition of done for every task

- implementation and migration, where applicable;
- unit/fixture/API tests;
- explicit failure behavior;
- structured logging without secrets;
- architecture or operator documentation update;
- no unexplained test warnings or skipped failures;
- reviewable commit with no runtime artifacts.
