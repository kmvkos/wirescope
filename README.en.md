# WireScope

[Русский](README.md) · **English**

WireScope is a self-contained Linux network auditor. It can run on a dedicated PC, laptop, server, virtual machine, or ARM64 device and be used as a portable appliance for inspecting an unfamiliar network segment.

WireScope observes the network passively first. The operator then explicitly confirms the allowed active scope. The system builds inventory, runs active discovery and protocol audits, produces findings, analyzes retained PCAP, builds topology, and can correlate persisted results from different sources. Reachability from the host is never treated as scanning authorization by itself.

Supported targets include Debian/Ubuntu, Fedora/RHEL/Rocky, and openSUSE on `amd64` and `arm64`. Raspberry Pi is one possible hardware platform, not a requirement.

## Workflow

```text
connect to network
        ↓
host / interface state
        ↓
passive observation
        ↓
operator-confirmed active scope
        ↓
Discovery / Standard / Deep
        ↓
inventory + services
        ↓
protocol audits
        ↓
findings + evidence
        ↓
Audit Report

separate retained PCAP
        ↓
Traffic Analysis
        ↓
optional: Network Topology overlay / Correlated Assessment
```

A separate **Listening** mode records PCAP from a selected interface with an optional BPF/tcpdump filter, duration, and size limit.

## Main capabilities

### Passive analysis

`dumpcap` performs bounded capture and `tshark` decodes the retained data. WireScope extracts Ethernet/MAC, VLAN/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS, and SSDP observations.

Observations remain separate from assumptions: ARP does not prove a subnet mask, and untagged traffic never receives an invented VLAN ID.

### Active discovery

Nmap runs only inside operator-confirmed scope. `discovery`, `standard`, and `deep` profiles are declared in `config/active_profiles.json`; arbitrary Nmap command lines are not accepted through the API.

### Inventory

Passive and active observations converge into normalized inventory. Identity correlation is conservative: MAC/IP are evidence, while hostname alone is not enough to merge assets. Conflicts remain explicit as `identity_conflict`.

Assets receive a confidence-rated device-class hint (`server-like`, `workstation-like`, `network-device-like`, `printer-like`, `iot-like`, `unknown`). This is an inventory hint, not a finding.

### Protocol audits and findings

After discovery, WireScope starts only read-only/diagnostic modules appropriate for discovered services: SSH, TLS, HTTP/HTTPS, SMB, DNS, SNMP, and LDAP.

Protocol modules persist observations. A separate rule engine produces findings over normalized facts. A finding contains severity, confidence, asset/service references, rationale, recommendation, and evidence references.

### Audit Report

Audit Report is the source-of-truth for the audit itself:

- inventory;
- discovered services;
- protocol-audit results;
- findings;
- rationale/recommendations;
- audit evidence.

Self-contained HTML, canonical `audit-report` v1 JSON, and Markdown are available. Reports are rendered from persisted data without re-scanning.

### PCAP Traffic Analysis

Retained PCAP is analyzed by a separate durable job without starting a new capture or contacting the network.

Traffic Analysis owns **what was observed during a specific capture window**:

- duration/frames/bytes/rates;
- top talkers and communications graph;
- TCP health;
- DNS latency/errors;
- ARP/DHCP/ICMP diagnostics;
- broadcast/multicast contributors;
- TLS/HTTP/QUIC/SMB metadata without payload decryption;
- ACK RTT summaries;
- comparison of retained analyses.

The canonical result is `traffic-analysis` JSON. The latest PCAP is never silently mixed into topology or other results.

### Network Topology

WireScope builds explainable topology from persisted evidence. Structural, L2, L3, Traffic, All Evidence, VLAN focus, and historical compare views are available.

Sources include inventory, ARP/ND, routes, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery, an explicitly selected Traffic Analysis, and optional read-only SNMP/SSH enrichment.

`coverage` / claimability reports `sufficient / partial / missing`. When evidence is insufficient, WireScope reports the limitation instead of guessing a gateway, physical link, VLAN, or Wi-Fi attachment.

Management-learned topology never expands active scope.

See [docs/en/TOPOLOGY_MODEL.md](docs/en/TOPOLOGY_MODEL.md).

### Correlated Assessment — v1.3

**Correlated Assessment** (Russian UI: **«Корреляция результатов»**) compares an already-persisted audit with one explicitly selected Traffic Analysis and topology.

It shows cross-source relationships only, for example:

- inventory assets exact-matched to traffic;
- discovered service ports observed in the selected capture;
- findings attached to assets/services visible in traffic;
- traffic endpoints not matched to inventory;
- exact-correlated internal assets communicating with globally routable endpoints;
- gateway/DHCP/DNS observations that agree or diverge across independent sources.

It is **not a second Audit Report and not a second Traffic Analysis**. Full source reports are not duplicated; a source fact appears only when required to explain a relationship.

The feature is fully offline: no scanner is started, PCAP is not re-read, and no new network I/O occurs.

For backward compatibility, internal job/schema/API identifiers remain `global_analysis`, `global-analysis`, and `/global-analysis`.

See [docs/en/GLOBAL_ANALYSIS_MODEL.md](docs/en/GLOBAL_ANALYSIS_MODEL.md).

## Web/kiosk and operations

The GUI exposes the durable pipeline and persisted audits. Auditors can use diagnostics, operational audit log, retention preview/cleanup, job recovery, and backup/restore. Viewers can read permitted persisted results without starting mutating jobs.

Key runtime endpoints:

```text
GET /api/v1/health
GET /api/v1/ready
GET /api/v1/capabilities
GET /api/v1/diagnostics
```

A normal appliance install listens on `0.0.0.0:8000`; the local kiosk opens `http://127.0.0.1:8000/`. Firewall, loopback-only bind, reverse proxy, and TLS remain deployment controls.

## Recovery and lifecycle

If the worker restarts during a job, the running job becomes `interrupted` and stale resource locks are released. Explicit retry creates a new durable job and never rewrites history.

Credentialed `snmp_topology` and `ssh_topology` jobs never reuse consume-once credentials. Retention is conservative: raw evidence is removed only through explicit preview/confirm cleanup.

SQLite + evidence backup/restore is part of the appliance CLI.

See [docs/en/OPERATIONS.md](docs/en/OPERATIONS.md).

## Architecture

WireScope is a modular monolith. API and worker run as separate processes over the same local state model.

```text
browser / kiosk
      │
      ▼
FastAPI /api/v1
      │
      ├── audits / durable jobs
      ├── inventory / findings / reports
      ├── traffic analysis / topology
      ├── correlated assessment
      └── diagnostics / lifecycle
      │
      ▼
SQLite + evidence store
      ▲
      │
worker
      ├── passive / capture
      ├── active discovery
      ├── protocol audits
      ├── traffic analysis
      ├── SNMP/SSH topology enrichment
      ├── correlated assessment
      └── findings / reports
```

`wirescope-api` and `wirescope-worker` run unprivileged. Packet-capture privileges are limited to `dumpcap`. External commands are constructed as argv and do not use `shell=True`.

See [docs/en/ARCHITECTURE.md](docs/en/ARCHITECTURE.md).

## Quick installation

The repository is private, so GitHub SSH/token access is required.

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope

# Switch to the intended checkpoint/tag for reproducible deployment.

cd ..
sudo mv wirescope /opt/wirescope
cd /opt/wirescope

sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

Main paths:

```text
/opt/wirescope       code + .venv
/etc/wirescope       configuration
/var/lib/wirescope   SQLite, runtime, evidence, backups
```

See [docs/en/INSTALLATION.md](docs/en/INSTALLATION.md).

## Development and CI

Python 3.11+ is required.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
.venv/bin/pytest
```

GitHub Actions runs compileall, the default pytest suite, browser regression, JavaScript syntax checks for feature UI, wheel build, and an installed-wheel smoke test outside the source tree.

## Current stage

**v1.3 Correlated Assessment is complete and live-validated.**

The next stage is a **Product Coherence Review** across Audit Report, Traffic Analysis, Network Topology, Correlated Assessment, and dashboard/operator views. The objective is to establish source-of-truth ownership for every information class and remove duplicated report blocks.

External PCAP import is considered a separate future feature and is intentionally not specified yet.

See [docs/en/ROADMAP.md](docs/en/ROADMAP.md).
