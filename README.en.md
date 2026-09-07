# WireScope

[Русский](README.md) · **English**

WireScope is a self-contained Linux network auditor. It can run on a dedicated PC, laptop, server, virtual machine, or ARM64 device, including Raspberry Pi, and be used as a portable appliance for inspecting an unfamiliar network segment.

WireScope observes the network passively first. Active checks run only after the operator explicitly confirms the allowed scope. Reachability from the host is never treated as scanning authorization by itself.

Supported platforms:

- Debian / Ubuntu / Raspberry Pi OS;
- Fedora / RHEL / Rocky;
- openSUSE;
- `amd64` and `arm64`.

## What WireScope does

Main workflow:

```text
connect to network
        ↓
passive observation
        ↓
confirm active scope
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
```

PCAP workflow:

```text
retained or imported PCAP
        ↓
Traffic Analysis
        ↓
Network Topology
        ↓
Correlated Assessment
```

### Passive discovery

`dumpcap` performs bounded capture and `tshark` decodes the PCAP. WireScope extracts Ethernet/MAC, VLAN/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS, and SSDP observations.

### Active discovery

Nmap runs only inside operator-confirmed scope. `discovery`, `standard`, and `deep` profiles are available. Arbitrary Nmap command lines are not accepted through the API.

### Inventory, protocol audits, and findings

Passive and active observations converge into normalized inventory. After discovery, WireScope runs only read-only/diagnostic checks appropriate for discovered services: SSH, TLS, HTTP/HTTPS, SMB, DNS, SNMP, and LDAP.

Protocol modules persist observations. A separate rule engine produces findings with severity, confidence, rationale, recommendation, and evidence references.

### Audit Report

Audit Report is the source of truth for the audit itself:

- inventory;
- discovered services;
- protocol-audit results;
- findings;
- rationale and recommendations;
- audit evidence.

Self-contained HTML, canonical `audit-report` v1 JSON, and Markdown are available.

### Traffic Analysis

Traffic Analysis works on already-retained PCAP and does not contact the network. It reports facts from the selected capture window: volume/rates, top talkers, communications graph, TCP health, DNS latency/errors, ARP/DHCP/ICMP diagnostics, broadcast/multicast contributors, and protocol metadata.

### Manual PCAP import — v1.4

External `.pcap`, `.pcapng`, and gzip-wrapped captures can be uploaded through the Web UI/API. Import is offline: WireScope does not start packet capture, discovery, or protocol probes, and addresses observed only in imported traffic never expand active scope.

After format, size, and SHA-256 validation, an imported capture becomes a normal persisted `packet_capture`. The operator can then explicitly start Traffic Analysis and, if required, Correlated Assessment.

### Network Topology

Topology is built from persisted evidence: inventory, ARP/ND, routes, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery, an explicitly selected Traffic Analysis, and optional SNMP/SSH enrichment.

When evidence is incomplete, WireScope reports `sufficient / partial / missing` instead of inventing a gateway, physical link, or VLAN.

### Correlated Assessment

Correlated Assessment compares an already-persisted audit with an explicitly selected Traffic Analysis and topology. It reports cross-source relationships and evidence gaps rather than duplicating Audit Report or Traffic Analysis.

For backward compatibility, internal identifiers remain `global_analysis`, `global-analysis`, and `/global-analysis`.

## Architecture and privileges

WireScope is a modular monolith. API and worker run as separate unprivileged processes over SQLite + evidence storage.

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
```

Raw packet-capture privileges are limited to `/usr/bin/dumpcap` via `cap_net_admin,cap_net_raw`. API and worker never run as root.

See [docs/en/ARCHITECTURE.md](docs/en/ARCHITECTURE.md) and [docs/en/SECURITY_MODEL.md](docs/en/SECURITY_MODEL.md).

## Quick installation

The repository is public. For a normal system installation, use `/opt/wirescope`.

```bash
git clone https://github.com/kmvkos/wirescope.git
sudo mv wirescope /opt/wirescope
cd /opt/wirescope

sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

> System installs from `/home/...` are intentionally rejected by the installer because generated systemd units use `ProtectHome=true`. Move the checkout to `/opt/wirescope` first.

Main paths:

```text
/opt/wirescope       code + .venv
/etc/wirescope       configuration
/var/lib/wirescope   SQLite, runtime, evidence, backups
```

After installation:

```bash
systemctl is-active wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/v1/ready
sudo cat /etc/wirescope/initial-admin.txt
```

The default username is `auditor`.

See [docs/en/INSTALLATION.md](docs/en/INSTALLATION.md).

## Kiosk

`--with-kiosk --enable-kiosk` installs a minimal local display stack with Chromium and Cage or Xorg/xinit. A full desktop environment is not required.

The kiosk opens `http://127.0.0.1:8000/` on `tty1`. API and worker remain independent of Chromium and keep running if the kiosk restarts.

## Development and CI

Python 3.11+:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
.venv/bin/pytest
```

GitHub Actions runs compileall, the default pytest suite, browser regression, JavaScript syntax checks, wheel build, and an installed-wheel smoke test.

## Current release line

The current line is **v1.4 Manual PCAP Import**, built on completed v1.1 Traffic Analysis, v1.2 Network Topology, and v1.3 Correlated Assessment work.

Key documents:

| Document | Contents |
| --- | --- |
| [Installation](docs/en/INSTALLATION.md) | install, kiosk, bind, TLS, upgrade/rollback |
| [API](docs/en/API.md) | `/api/v1`, jobs, evidence, topology, correlation |
| [Architecture](docs/en/ARCHITECTURE.md) | modules, data flow, jobs, persistence |
| [PCAP management](docs/en/PCAP_MANAGEMENT.md) | retained/imported capture lifecycle |
| [Topology](docs/en/TOPOLOGY_MODEL.md) | evidence graph, coverage, L2/L3/VLAN |
| [Correlated Assessment](docs/en/GLOBAL_ANALYSIS_MODEL.md) | cross-source correlation and evidence gaps |
| [Operations](docs/en/OPERATIONS.md) | diagnostics, recovery, retention, backup/restore |
| [Roadmap](docs/en/ROADMAP.md) | completed milestones and next work |
