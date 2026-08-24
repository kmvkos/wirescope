# WireScope

[Русский](README.md) · **English**

WireScope is a self-contained network audit appliance for Linux. It can run on a dedicated PC, laptop, server, virtual machine, or ARM64 device and is intended as a portable tool for examining an unfamiliar network segment.

The workflow is simple: observe the network passively, let the operator explicitly confirm the authorized active scope, then build inventory, dispatch service-aware checks, evaluate findings, and produce a report. A route being reachable from the host does not make it authorized scan scope.

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
protocol checks
        ↓
findings + evidence
        ↓
HTML / JSON / Markdown report
```

A separate **Listen / Record** mode records PCAPs with a selected interface, optional BPF/tcpdump filter, time limit, and maximum file size.

## What WireScope does

### Passive analysis

`dumpcap` performs bounded capture. The resulting PCAP is decoded once through `tshark -T ek`, then normalized packet records are processed by in-process sensors.

Coverage includes Ethernet/MAC, 802.1Q/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS, and SSDP.

Observations remain separate from assumptions. An ARP address is not proof of a subnet mask, and untagged traffic does not receive an invented VLAN ID.

### Active discovery

Nmap runs only inside operator-confirmed scope. The API does not accept arbitrary Nmap flags.

The `discovery`, `standard`, and `deep` profiles are declarative in `config/active_profiles.json`. Operators can change supported profile parameters but cannot inject arbitrary command-line material such as `-sC` or `--script vuln`.

### Inventory and correlation

Passive and active observations converge into one inventory. Stable identity prefers MAC, then IP. Conflicting identity signals are preserved as `identity_conflict` rather than silently merging devices. A hostname alone is not enough to merge assets.

Each asset receives a confidence-rated device-class hint:

- `server-like`;
- `workstation-like`;
- `network-device-like`;
- `printer-like`;
- `iot-like`;
- `unknown`.

Classification is an inventory hint, not a security finding.

### Protocol checks

After discovery, WireScope dispatches only modules that match discovered services:

- SSH — `ssh-audit`;
- TLS — `openssl s_client`;
- HTTP/HTTPS — `curl`;
- SMB — `smbclient`;
- DNS — `dig`;
- SNMP — conservative SNMPv3 noAuth probe;
- LDAP — anonymous base DSE with `ldapsearch`.

The modules do not guess passwords or community strings. `testssl.sh`, Nikto, and Nuclei remain `never-default`.

### Findings, evidence, and reports

Protocol modules persist observations. A separate rule engine evaluates normalized facts and creates findings, keeping raw evidence separate from interpretation.

A finding records severity, confidence, affected asset/service, rationale, recommendation, and evidence references. Text/JSON/XML evidence can be inspected directly from the UI.

Reports are built from persisted data without re-running scanners:

- self-contained HTML;
- JSON `audit-report` v1;
- Markdown.

PDF is not a v1.0 release requirement.

## Overview and operations

The GUI exposes the durable pipeline:

```text
passive → discovery → protocol → findings → report
```

The **Overview** panel shows:

- asset/service counts;
- findings by severity;
- device classes;
- passive/active correlation;
- common open services;
- external-tool availability;
- loaded scan profiles;
- audit-to-audit diff;
- finding evidence.

Auditors also get an **Operations** tab with:

- SQLite/migration/worker/core-tool health;
- free disk and evidence-store usage;
- retention policy and cleanup preview;
- operational audit log;
- retry for failed/interrupted/cancelled stages;
- diagnostics JSON export.

## Recovery and lifecycle

If the worker restarts during a job, the running job becomes `interrupted` and stale resource locks are released. The operator can retry the affected terminal stage. Retry creates a **new** durable job with the same parameters and keeps the original history unchanged.

Default retention candidates are:

- temporary artifacts — 24 hours;
- debug — 7 days;
- PCAP — 30 days;
- Nmap XML / protocol raw evidence — 90 days.

Raw evidence is not deleted unexpectedly in the background: an auditor sees a preview first and must explicitly confirm cleanup. Normalized inventory, findings, and reports are not automatically deleted.

SQLite + evidence backup/restore is available through the appliance CLI.

See [Operations](docs/en/OPERATIONS.md).

## Operational audit log

WireScope stores a separate log of significant operator actions: login/logout/password change, audit-stage starts, cancel/retry, network changes, finding changes, report generation, and maintenance cleanup.

Passwords, request bodies, session tokens/cookies, and provider stdout are not copied into this log.

## Architecture

WireScope is a modular monolith. API and worker are separate processes that use one local state model.

```text
browser / kiosk
      │
      ▼
FastAPI
      │
      ├── backend/routers/
      ├── auth / network / scope
      ├── audits / durable jobs
      ├── inventory / correlations
      ├── findings / evidence / reports
      ├── diagnostics / lifecycle / audit log
      │
      ▼
SQLite + evidence store
      ▲
      │
worker
      ├── passive discovery
      ├── packet capture
      ├── active discovery
      ├── protocol audits
      ├── findings evaluation
      └── report generation
```

`backend/app.py` is the composition root. HTTP routes are grouped by domain under `backend/routers/`.

SQLite runs in WAL mode. Normalized data and artifact metadata stay in the database; PCAPs, Nmap XML, raw provider evidence, and reports live in the evidence store and are registered by UUID, size, and SHA-256.

See [Architecture](docs/en/ARCHITECTURE.md).

## API

The canonical API is `/api/v1/*`. `/api/*` remains as a hidden compatibility alias for existing clients.

Alongside the audit/job endpoints, v1 includes:

```text
GET  /api/v1/capabilities
GET  /api/v1/scan-profiles
GET  /api/v1/audits/{id}/dashboard
GET  /api/v1/audits/{id}/correlations
GET  /api/v1/audits/{id}/diff?against={old_id}
GET  /api/v1/audits/{id}/findings/{finding_id}/evidence
POST /api/v1/jobs/{job_id}/retry
GET  /api/v1/diagnostics
GET  /api/v1/audit-log
GET  /api/v1/maintenance/status
POST /api/v1/maintenance/cleanup
```

See [API documentation](docs/en/API.md).

## Web interface and bind policy

A normal WireScope appliance listens on **`0.0.0.0:8000`**. This is intentional: the UI should be reachable through any configured Ethernet/Wi-Fi interface on the device.

The local kiosk opens `http://127.0.0.1:8000/` because it runs on the same host.

A deployment that needs a different policy can explicitly use a firewall, `--bind-host 127.0.0.1`, reverse proxy, or TLS.

## Privilege model

`wirescope-api` and `wirescope-worker` do not run as root. Packet-capture privileges belong only to `/usr/bin/dumpcap`.

WireScope does not grant Nmap extra capabilities. When raw sockets are unavailable, the provider uses safe unprivileged fallbacks.

## Quick install

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance
cd ..
sudo mv wirescope /opt/wirescope
cd /opt/wirescope

sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

Normal install/upgrade entrypoints use `0.0.0.0` automatically.

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

GitHub Actions runs `compileall` and the default pytest suite. `network` and `live_pi` tests remain opt-in.

## The finish line

The next formal milestone is **WireScope v1.0 RC1**. It is defined by operational release gates rather than by the number of scanners: install/upgrade, persistence, full audit workflow, recovery, retention, operational logging, diagnostics, backup, and a live smoke test on an installed appliance.

See [v1 release readiness](docs/en/RELEASE_READINESS.md).

Until the live smoke test passes on an installed VM, the current code remains a development candidate even with green CI. After that test succeeds, `v1.0.0-rc1` is the appropriate tag.

## Documentation

| Document | Contents |
| --- | --- |
| [API](docs/en/API.md) | `/api/v1`, jobs, evidence, diagnostics, maintenance |
| [Installation](docs/en/INSTALLATION.md) | install, kiosk, bind, TLS, upgrade/rollback |
| [Architecture](docs/en/ARCHITECTURE.md) | modules, data flow, jobs, persistence |
| [Operations](docs/en/OPERATIONS.md) | diagnostics, recovery, retention, backup/restore |
| [v1 readiness](docs/en/RELEASE_READINESS.md) | mandatory RC1 release gate |
| [Scanning model](docs/en/SCANNING_MODEL.md) | scope, profiles, inventory, protocol audits |
| [Security model](docs/en/SECURITY_MODEL.md) | trust boundaries, auth, evidence, privileges |
| [Findings model](docs/en/FINDINGS_MODEL.md) | rules, severity/confidence, state model |
| [Reporting](docs/en/REPORTING_MODEL.md) | `audit-report` v1, HTML/JSON/Markdown |
| [Operator GUI](docs/en/GUI_MODEL.md) | wizard, dashboard, diff, evidence |
| [Development](docs/en/DEVELOPMENT.md) | local run, migrations, tests |
| [Runbook](docs/en/RUNBOOK.md) | operational troubleshooting |

## Post-1.0 roadmap

After RC1/1.0, new functionality can continue without moving the first-release finish line: additional protocol modules, PDF, topology graph, CVE enrichment, scheduled audits, deeper historical identity correlation, and further frontend decomposition.
