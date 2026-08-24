# WireScope development roadmap

[Русский](../IMPLEMENTATION_PLAN.md) · **English**

This file records project history and the current roadmap. Documentation for **how WireScope behaves today** lives in [ARCHITECTURE.md](ARCHITECTURE.md), [SCANNING_MODEL.md](SCANNING_MODEL.md), [SECURITY_MODEL.md](SECURITY_MODEL.md), and the other subsystem guides.

## Current status

WireScope has gone through eight major development stages.

```text
M0  prototype stabilization               complete
M1  passive foundation                    complete
M2  jobs + persistence                    complete
M3  active discovery                      complete
M4  service-aware protocol audits         complete
M5  findings engine                       complete
M6  reporting                             complete
M7  operator GUI + local auth             complete
M8  generic Linux appliance               active
```

M0–M7 are implemented and used by the current branch. M8 already contains most appliance functionality — installer, systemd integration, kiosk mode, backup/restore, distro detection, network helper, and deployment hardening — but it should not be considered fully closed until cross-distribution release verification and the remaining operational work are complete.

Current working branch:

```text
milestone-8-appliance
```

## Project-wide rules

A few constraints apply regardless of milestone:

- Python 3.11+;
- generic Linux on `amd64` and `arm64`;
- backend and worker do not run as root;
- provider execution does not use `shell=True`;
- packet-capture privileges belong only to `dumpcap`;
- active scanning stays inside explicitly confirmed scope;
- raw evidence remains separate from normalized data;
- live-network tests are opt-in;
- provider/parser failure is not interpreted as protocol absence;
- new providers and parsers require fixture/unit/API coverage;
- runtime behavior changes must be reflected in the relevant subsystem documentation.

---

# M0 — Prototype stabilization — complete

The first stage was not about adding features. It turned the early prototype into a codebase that could be developed safely.

Work included:

- fixing syntax and import errors;
- removing obvious duplicate/dead code;
- centralizing filesystem paths in settings;
- adding `pyproject.toml`;
- creating a reproducible virtualenv/dependency setup;
- adding initial API/settings/environment/sensor tests;
- documenting current and target architecture;
- defining the development roadmap.

The practical result was a repeatable baseline rather than a project tied to the incidental state of one VM.

---

# M1 — Passive foundation — complete

M1 replaced the early passive scanner with a bounded, repeatable pipeline.

## Tool runner

A common controlled runner was introduced with:

- argv arrays instead of shell command strings;
- timeout support;
- cancellation;
- exit code/stdout/stderr capture;
- tool-version metadata;
- structured error categories;
- bounded output.

## Interface policy

Interfaces are discovered and validated before a capture provider receives the interface name. Unknown, loopback, or policy-denied interfaces are not forwarded directly to `dumpcap`.

## Capture/decode pipeline

The current shape was established here:

```text
interface
   ↓
dumpcap → bounded PCAP
   ↓
tshark -T ek
   ↓
PacketRecord
   ↓
passive sensors
   ↓
assessment
```

A live passive audit uses one `dumpcap` and one `tshark`, rather than one tshark process per protocol sensor.

## Sensors

The passive set includes:

- Ethernet/MAC;
- VLAN/QinQ;
- ARP;
- DHCPv4;
- LLDP/CDP;
- STP;
- IPv6 RA/ND;
- DHCPv6;
- mDNS;
- LLMNR;
- NBNS;
- SSDP.

## Assessment

The confidence model and the “do not claim more than the evidence supports” rule were introduced here.

Examples:

- ARP `/24` grouping is only a hint;
- untagged traffic is not assigned an invented VLAN ID;
- LLDP/CDP PVID is not treated as an 802.1Q tag observed in the capture.

See [ARCHITECTURE.md](ARCHITECTURE.md).

---

# M2 — Durable jobs and persistence — complete

M2 removed process-local job state and made audit workflows resilient to API/browser restarts.

## SQLite

SQLAlchemy 2, Alembic, and appliance-local SQLite were added.

The database uses:

- WAL;
- foreign keys;
- busy timeout;
- short transactions;
- `synchronous=FULL` by default.

## Job model

Durable states became:

```text
queued
running
completed
failed
cancelled
interrupted
```

Job metadata, progress, events, cancellation requests, and result references are persisted.

## API / worker split

The production process model became:

```text
wirescope-api
wirescope-worker
```

The API enqueues work. The worker claims and executes it.

The GUI and API request that created a job no longer own its lifetime.

## Recovery and locks

This stage added:

- worker heartbeat;
- supervisor lease;
- restart recovery;
- resource locks;
- atomic artifact storage;
- startup cleanup of temporary/orphan files.

A job left running after a worker crash becomes `interrupted`; queued jobs remain queued.

---

# M3 — Active discovery — complete

M3 added controlled Nmap discovery and persistent asset/service inventory.

## Authorized scope

Observed network hints were explicitly separated from permission to scan.

Before Nmap runs:

- targets are canonicalized with `ipaddress`;
- size caps are enforced;
- unspecified/multicast targets are rejected;
- interface policy is checked;
- the real route is validated;
- an immutable confirmed-scope snapshot is stored.

## Nmap provider

A single Nmap execution path was introduced with XML evidence and normalized parsing.

Profiles:

- Discovery;
- Standard;
- Deep.

The backend is not granted raw-socket privileges just for Nmap. Without them, the provider uses TCP connect fallback.

NSE, `-sC`, vuln, brute, exploit, and DoS scripts are not part of active discovery.

## Inventory

M3 added:

- assets;
- addresses;
- names with provenance;
- services;
- OS/device hints;
- passive/active correlation.

Correlation uses exact MAC first, then exact IP. Conflicting identity evidence is recorded instead of silently merged.

See [SCANNING_MODEL.md](SCANNING_MODEL.md).

---

# M4 — Service-aware protocol audits — complete

After ordinary inventory, WireScope gained targeted checks for discovered services.

Current modules:

| Protocol | Tool |
| --- | --- |
| SSH | `ssh-audit` |
| TLS | `openssl s_client` |
| HTTP/HTTPS | `curl` |
| DNS | `dig` |
| SMB | `smbclient` |
| SNMP | `snmpget` |
| LDAP | `ldapsearch` |

Each module declares:

- service predicates;
- safety class;
- required binary;
- argv builder;
- parser;
- normalized observations;
- timeout;
- fixtures.

A module does not run merely because its binary is installed. A matching service must exist in inventory, and the target address must remain inside authorized scope.

Credential guessing, SNMP community brute force, and aggressive default scanners were intentionally excluded.

`testssl.sh`, Nikto, and Nuclei remain `never-default` stubs.

---

# M5 — Findings engine — complete

M5 separated security interpretation from scanner/provider output.

```text
observations
     ↓
versioned rules
     ↓
findings
```

Rules consume normalized data and do not parse raw tool stdout.

The model added:

- severity;
- confidence;
- recommendations;
- evidence links;
- deduplication;
- `suppressed`;
- `accepted_risk`;
- finding state history.

Initial rule families cover SSH, TLS, HTTP, SMB, DNS, SNMP, LDAP, insecure management protocols, and selected infrastructure observations.

See [FINDINGS_MODEL.md](FINDINGS_MODEL.md).

---

# M6 — Reporting — complete

M6 introduced reproducible audit reporting from persisted state.

Schema:

```text
audit-report v1
```

Exports:

- self-contained HTML;
- normalized JSON.

Report generation does not invoke scanners and does not resolve caller-supplied filesystem paths.

The report model includes:

- executive summary;
- environment;
- passive assessment;
- scope;
- inventory;
- findings;
- recommendations;
- evidence metadata;
- generation history;
- `source_hash`.

PDF was deliberately deferred until the HTML/report contract stabilized and remains unimplemented.

See [REPORTING_MODEL.md](REPORTING_MODEL.md).

---

# M7 — GUI and local authentication — complete

M7 made WireScope usable without shell access for the ordinary operator workflow.

Main flow:

```text
login
→ new audit
→ interface/network/scope
→ profile
→ passive/active/protocol jobs
→ summary
→ assets/observations/assessment/findings
→ report
```

This stage added:

- `auditor` and `viewer` roles;
- local SQLite users;
- session cookies;
- password changes;
- backend role enforcement;
- 480×320 kiosk layout;
- denser laptop layout;
- durable polling and page-reload recovery;
- separate observations/assessment/findings screens.

The same GUI foundation later gained:

- appliance network settings;
- **Listen / Record** with retained PCAP;
- BPF filter support;
- capture progress and download.

See [GUI_MODEL.md](GUI_MODEL.md).

---

# M8 — Generic Linux appliance — active

M8 is the current stage. Its purpose is not to add another scanner, but to turn the existing application into a Linux appliance that can be installed, operated, upgraded, and recovered predictably.

## Already implemented

### Generic Linux installer

The installer detects:

- `apt`;
- `dnf`;
- `yum`;
- `zypper`;
- `amd64`;
- `arm64`.

No Raspberry Pi-specific OS is required.

Both system install and `--user-install` are supported.

### Service account and paths

A system install uses the unprivileged `wirescope` account and separates:

```text
Git checkout      /opt/wirescope        recommended
configuration     /etc/wirescope
mutable data      /var/lib/wirescope
```

### `dumpcap` least privilege

The installer configures `dumpcap`, the `wireshark` group, and file capabilities without granting those capabilities to the Python interpreter/backend.

### systemd

Separate units exist for:

- API;
- worker;
- optional kiosk.

System units use `SupplementaryGroups=wireshark`. User units use `sg wireshark`.

### Kiosk

The autonomous mode works without a full desktop environment.

The system kiosk:

- owns `tty1`;
- waits for API health;
- opens Chromium;
- uses Cage or Xorg/xinit;
- uses the Xorg path on VMware;
- can restart without cancelling jobs.

### Local and remote operator modes

Supported deployment styles include:

- loopback kiosk;
- local browser;
- Caddy/nginx reverse proxy;
- direct Uvicorn TLS;
- explicit LAN bind.

### Backup / restore

The appliance CLI can back up and restore SQLite plus evidence.

### Upgrade

`packaging/upgrade.sh` supports re-running installation logic while preserving data/configuration and applying migrations.

### Host/network support

The appliance layer now includes:

- host/distribution detection;
- dependency inventory;
- network-control helper;
- readiness/verification helpers;
- self-signed TLS helper;
- release checksums;
- proxy/firewall examples.

### Listen / Record

The M8-era GUI/runtime also includes a separate `packet_capture` workflow with promiscuous `dumpcap`, optional BPF filtering, duration/file-size limits, and retained PCAP evidence.

## Work remaining before M8 is considered complete

### 1. Cross-distribution release verification

Fixture-based detection exists, but stable release qualification should include real smoke installs on at least:

- Debian/Ubuntu;
- one Fedora/RHEL/Rocky system;
- openSUSE as a separate target if practical;
- `amd64` and at least one real `arm64` host.

Verification should cover the full path rather than just installer exit status:

```text
install
→ migration
→ worker ready
→ login
→ passive fixture/live capture smoke
→ active discovery smoke
→ report
→ reboot
→ recovery
```

### 2. tshark compatibility matrix

Parser fixtures target a verified tshark 4.x family, but distribution packages may expose field-layout/version differences.

Before release, document a compatibility matrix and run smoke tests against the package versions shipped by supported distributions.

### 3. Retention policy

Startup maintenance already removes controlled temporary/orphan files, but there is no full policy-driven deletion of completed audits and registered evidence.

A future retention design needs explicit rules for:

- audit metadata lifetime;
- PCAP/raw evidence lifetime;
- report retention;
- safe delete transactions;
- operator override/export-before-delete.

### 4. Security audit log

Operational structured logs, finding state events, and job events already exist, but there is no dedicated security audit-log table for sensitive actions.

Potential events include:

- login failures;
- password changes/resets;
- network configuration changes;
- scope confirmations;
- finding state changes;
- report exports;
- privileged helper failures.

### 5. Explicit retry workflow

Terminal jobs are not retried automatically, which is the correct safe default.

A future **manual retry** should create a new job linked explicitly to the previous attempt rather than mutating the old terminal job back to running.

### 6. API route decomposition

`backend/app.py` has become large. The runtime architecture still works, but future maintenance will benefit from splitting HTTP routes into router modules and narrower domain-facing dependencies.

This is refactoring debt, not a current functional blocker.

### 7. Optional Raspberry Pi hardware validation

Raspberry Pi is no longer the primary platform, but real ARM64/Pi kiosk smoke testing remains useful as an optional release target:

- display/touch;
- Chromium kiosk;
- dumpcap;
- thermal/resource behavior;
- reboot recovery.

It must not turn Raspberry Pi OS back into a requirement for the whole project.

---

# After M8

The next milestone number is intentionally not fixed yet. Once the appliance layer is stable, new features should be chosen from real audit use cases rather than by adding scanners for feature-count alone.

Possible directions include:

## More protocol coverage

Potential modules:

- FTP;
- SMTP;
- RDP;
- Redis;
- PostgreSQL;
- MySQL/MariaDB;
- MSSQL;
- MongoDB;
- Elasticsearch;
- MQTT;
- UPnP;
- IPMI;
- NTP;
- TFTP;
- Telnet;
- VNC;
- Docker API;
- Kubernetes API.

Each should start with a safe observation contract before finding rules are added.

## PDF

PDF should be added only on top of the stable HTML/report model. A PDF renderer must not become a new network-data source or a separate truth model.

## Authenticated audits

WireScope currently works mostly without credentials. Authenticated SSH/LDAP/AD/SMB/API checks would require a separate credential-storage and security model before provider implementation.

## Better asset identity

Current correlation is deliberately conservative. A richer future identity model is possible, but weak heuristic signals should not silently merge hosts.

## Export/API versioning

As external integrations appear, public API contracts will need explicit versioning in addition to report-schema versioning.

---

# Definition of done for new runtime work

New behavior should normally include:

- implementation;
- migration if schema changes;
- unit/fixture/API tests;
- explicit failure behavior;
- cancellation/timeout when external tools are involved;
- no secrets in logs or unit files;
- updates to the relevant documentation;
- no accidental live-network work in default pytest;
- reviewable commits without runtime artifacts.

The guiding rule remains simple: WireScope should do exactly what it tells the operator it is doing, and lack of evidence should never be silently promoted into a confident conclusion.
