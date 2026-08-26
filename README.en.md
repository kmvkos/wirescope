# WireScope

[Русский](README.md) · **English**

WireScope is a self-contained network audit appliance for Linux. It can run on a dedicated PC, laptop, server, virtual machine, or ARM64 device and is intended as a portable tool for examining an unfamiliar network segment.

WireScope first observes the network passively, then requires the operator to explicitly confirm authorized active scope. It can then build inventory, perform active discovery and protocol audits, evaluate findings, analyze retained PCAP, build network topology, and generate reports. Reachability from the host is never treated as scan authorization by itself.

Supported platforms include Debian/Ubuntu, Fedora/RHEL/Rocky, and openSUSE on `amd64` and `arm64`. Raspberry Pi is one supported hardware option, not a requirement.

## Audit workflow

```text
connect to a network
        ↓
host and interface state
        ↓
passive capture
        ↓
ARP / DHCP / VLAN / LLDP / CDP / STP / IPv6 / mDNS / LLMNR / NBNS / SSDP
        ↓
operator confirms authorized scope
        ↓
active discovery
        ↓
assets + services
        ↓
protocol audits
        ↓
findings + evidence
        ↓
report / traffic analysis / topology
```

A separate **Listen / Record** mode saves PCAP using a selected interface, optional BPF/tcpdump filter, duration, and maximum file size.

## What WireScope does

### Passive analysis

`dumpcap` performs bounded capture. The resulting PCAP is decoded once through `tshark -T ek`, and normalized packet records are processed by in-process sensors.

Coverage includes Ethernet/MAC, 802.1Q/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS, and SSDP.

Observations remain separate from assumptions. An ARP address is not proof of a subnet mask, and untagged traffic does not receive an invented VLAN ID.

### Active discovery

Nmap runs only inside operator-confirmed scope. The API does not accept arbitrary Nmap flags.

The `discovery`, `standard`, and `deep` profiles are declarative in `config/active_profiles.json`. Clients cannot inject arbitrary command-line material such as `-sC` or `--script vuln`.

### Inventory and correlation

Passive and active observations converge into one inventory. Stable identity prefers MAC, then IP. Conflicting signals are preserved as `identity_conflict` rather than silently merging devices. Hostname alone is never enough to merge assets.

Each asset receives a confidence-rated device-class hint:

- `server-like`;
- `workstation-like`;
- `network-device-like`;
- `printer-like`;
- `iot-like`;
- `unknown`.

Classification is an inventory hint, not a security finding.

### PCAP Traffic Analysis

A retained PCAP can be analyzed by a separate durable job without another capture.

Traffic Analysis provides top talkers and a communications graph, rate/volume statistics, TCP health, DNS latency/errors, ARP/DHCP/ICMP diagnostics, broadcast/multicast contributors, TLS/HTTP/QUIC/SMB metadata, ACK RTT summaries, and comparison of two persisted analyses.

The canonical result is `traffic-analysis` JSON. Its communications graph can be **explicitly** attached to Network Topology; the latest PCAP is never mixed automatically.

### Network Topology

WireScope builds topology as an auditor: it retains a complete evidence graph while presenting a separate structural / infrastructure-first diagram to the operator.

Views include:

- Structural;
- L2;
- L3;
- Traffic;
- All Evidence;
- VLAN focus;
- historical topology comparison.

Inputs include inventory, ARP/ND, interface routes, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery, Traffic Analysis, and optional read-only SNMP/SSH management enrichment.

Topology reports `coverage` / claimability for `inventory`, `l3`, `l2`, `traffic`, `vlan`, `wifi`, and `hypervisor` as:

```text
sufficient
partial
missing
```

This is not a “percentage of the network discovered.” When evidence is insufficient, WireScope tells the operator **what evidence is missing** instead of inventing physical links or VLAN membership.

JSON/SVG/PNG export, subnet regions, zoom/pan/fit, asset/edge details, findings, and global retained-audit topology are supported.

See [Network Topology model](docs/en/TOPOLOGY_MODEL.md).

### Management-plane enrichment

For suitable managed devices, topology can be enriched from read-only management sources:

- SNMPv2c/v3 using IF/IP/BRIDGE/Q-BRIDGE/LLDP MIBs;
- SSH for Linux/OpenWrt-like systems using a fixed `ip/bridge/iw` allowlist.

SNMP/SSH targets must remain inside confirmed scope. SSH requires strict host-key verification and accepts no arbitrary remote command. Credentials use an ephemeral consume-once spool and are not retained as plaintext topology evidence.

A subnet learned from management data expands topology knowledge but remains `active_scope=false`.

### Protocol checks

After discovery, WireScope dispatches only modules that match discovered services:

- SSH — `ssh-audit`;
- TLS — `openssl s_client`;
- HTTP/HTTPS — `curl`;
- SMB — `smbclient`;
- DNS — `dig`;
- SNMP — conservative SNMP probe;
- LDAP — anonymous base DSE with `ldapsearch`.

The modules do not automatically guess passwords or community strings. `testssl.sh`, Nikto, and Nuclei remain `never-default`.

### Findings, evidence, and reports

Protocol modules persist observations. A separate rule engine evaluates normalized facts and creates findings, keeping raw evidence separate from interpretation.

A finding records severity, confidence, asset/service, rationale, recommendation, and evidence references.

Reports are built from persisted data without re-running scanners:

- self-contained HTML;
- JSON `audit-report` v1;
- Markdown.

## Overview and operations

The GUI exposes durable audits and pipeline state. Auditors also get diagnostics, operational audit log, retention preview/cleanup, job recovery, and appliance backup/restore.

Key runtime endpoints:

```text
GET /api/v1/health
GET /api/v1/ready
GET /api/v1/capabilities
GET /api/v1/diagnostics
```

## Recovery and lifecycle

If the worker restarts during a job, the running job becomes `interrupted` and stale resource locks are released. Explicit retry creates a **new** durable job and keeps the source history unchanged.

Credentialed `snmp_topology` and `ssh_topology` jobs never reuse old one-time credentials; enrichment is started again with fresh credentials.

Raw evidence is never silently deleted in the background. An auditor sees a cleanup preview and explicitly confirms removal.

SQLite + evidence backup/restore is available through the appliance CLI.

See [Operations](docs/en/OPERATIONS.md).

## Architecture

WireScope is a modular monolith. API and worker are separate processes sharing one local state model.

```text
browser / kiosk
      │
      ▼
FastAPI /api/v1
      │
      ├── audits / durable jobs
      ├── inventory / findings / reports
      ├── traffic analysis / topology
      ├── diagnostics / lifecycle
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
      └── findings / reports
```

`backend/app.py` is the composition root. SQLite uses WAL mode; large raw artifacts live in the evidence store and are registered by UUID, size, and SHA-256.

See [Architecture](docs/en/ARCHITECTURE.md).

## API

The canonical API is `/api/v1/*`. `/api/*` remains a compatibility alias.

Topology endpoints:

```text
GET  /api/v1/audits/{audit_id}/topology
GET  /api/v1/topology/global
GET  /api/v1/audits/{audit_id}/topology/compare?against={baseline}
POST /api/v1/audits/{audit_id}/topology/snmp
POST /api/v1/audits/{audit_id}/topology/ssh
```

See [API documentation](docs/en/API.md).

## Web interface and bind policy

A normal appliance listens on `0.0.0.0:8000` so the GUI is reachable through configured appliance interfaces. The local kiosk opens `http://127.0.0.1:8000/`.

Firewall, loopback-only bind, reverse proxy, and TLS remain deployment controls.

## Privilege model

`wirescope-api` and `wirescope-worker` do not run as root. Packet-capture privileges belong only to `/usr/bin/dumpcap`.

WireScope does not elevate Nmap itself. SNMP/SSH enrichment also runs inside the unprivileged worker.

## Quick install

The repository is private, so a GitHub SSH key/token is required.

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope

# For reproducible deployment, switch to the intended release/tag/checkpoint.
# Do not use old milestone branches copied from historical instructions.

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
/opt/wirescope                  code + .venv
/etc/wirescope                  configuration
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             systemd units
```

See [Installation](docs/en/INSTALLATION.md).

## Development and CI

Python 3.11+ is required.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
.venv/bin/pytest
```

GitHub Actions run compileall, the default pytest suite, Chromium regression, wheel build, and an installed-wheel smoke test outside the source tree.

## Current stage

**Network Topology v1.2 is complete.** Structural topology passed live smoke on an upgraded WireScope VM. SNMP/SSH vendor-specific interoperability will continue to be checked when suitable managed devices are available and must never be replaced by heuristics.

The next stage is **v1.3 Global Correlation Analysis**: deterministic correlation of persisted inventory/findings/Traffic Analysis/Network Topology without new network I/O.

See [Roadmap](docs/en/ROADMAP.md).

## Documentation

| Document | Contents |
| --- | --- |
| [API](docs/en/API.md) | `/api/v1`, jobs, topology, evidence, diagnostics |
| [Installation](docs/en/INSTALLATION.md) | install, kiosk, bind, TLS, upgrade/rollback |
| [Architecture](docs/en/ARCHITECTURE.md) | modules, data flow, jobs, topology, persistence |
| [Network Topology](docs/en/TOPOLOGY_MODEL.md) | evidence graph, coverage, L2/L3/VLAN, SNMP/SSH, limits |
| [Operations](docs/en/OPERATIONS.md) | diagnostics, recovery, retention, backup/restore |
| [Scanning model](docs/en/SCANNING_MODEL.md) | scope, profiles, inventory, protocol audits |
| [Security model](docs/en/SECURITY_MODEL.md) | trust boundaries, auth, evidence, privileges |
| [Findings model](docs/en/FINDINGS_MODEL.md) | rules, severity/confidence, state model |
| [Reporting](docs/en/REPORTING_MODEL.md) | `audit-report` v1, HTML/JSON/Markdown |
| [Operator GUI](docs/en/GUI_MODEL.md) | wizard, dashboard, evidence, operator views |
| [Development](docs/en/DEVELOPMENT.md) | local run, migrations, tests |
| [Runbook](docs/en/RUNBOOK.md) | operational troubleshooting |
| [Roadmap](docs/en/ROADMAP.md) | current status and upcoming milestones |