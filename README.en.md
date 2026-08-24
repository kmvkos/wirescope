# WireScope

[Русский](README.md) · **English**

WireScope is a self-contained network audit appliance for Linux. It can run on a dedicated PC, laptop, server, virtual machine, or ARM64 device and is intended as a portable tool for examining an unfamiliar network segment.

The workflow is straightforward: observe the network passively first, let the operator confirm the authorized scope, then build an inventory, run checks that match discovered services, evaluate findings, and produce a report. A route being reachable from the host does not make it authorized scan scope.

Supported targets include Debian/Ubuntu, Fedora/RHEL/Rocky, and openSUSE on `amd64` and `arm64`. Raspberry Pi is one supported hardware option, not a requirement.

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

## What WireScope does today

### Passive analysis

`dumpcap` performs a bounded capture. The resulting PCAP is decoded once through `tshark -T ek`, and normalized packet records are processed by in-process sensors.

Current coverage includes Ethernet/MAC, 802.1Q/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS, and SSDP.

Observations remain separate from assumptions. An ARP address, for example, is not treated as proof of a subnet mask, and untagged traffic does not receive an invented VLAN ID.

### Active discovery

Nmap runs only inside operator-confirmed scope. The API does not accept arbitrary Nmap flags.

The `discovery`, `standard`, and `deep` profiles are now declarative and live in `config/active_profiles.json`. The format is deliberately bounded: operators can change supported profile parameters, but cannot inject arbitrary command-line material such as `-sC` or `--script vuln`.

### Inventory and correlation

Passive and active observations converge into one inventory. Stable identity prefers MAC and then IP. When identity signals conflict, WireScope records an `identity_conflict` instead of silently merging two devices. A hostname alone is not enough to merge assets.

Each asset receives a cautious device-class hint:

- `server-like`;
- `workstation-like`;
- `network-device-like`;
- `printer-like`;
- `iot-like`;
- `unknown`.

Classification is stored with confidence and source signals. It is an inventory hint, not a security finding.

### Protocol checks

After discovery, WireScope dispatches only modules that match discovered services:

- SSH — `ssh-audit`;
- TLS — `openssl s_client`;
- HTTP/HTTPS — `curl`;
- SMB — `smbclient`;
- DNS — `dig`;
- SNMP — a conservative SNMPv3 noAuth probe;
- LDAP — anonymous base DSE using `ldapsearch`.

The modules do not guess passwords or community strings. `testssl.sh`, Nikto, and Nuclei remain `never-default` and are not dispatched by normal profiles.

### Findings, evidence, and reports

Protocol modules persist observations. A separate rule engine evaluates those normalized facts and creates findings, keeping raw evidence separate from interpretation.

A finding records severity, confidence, affected asset/service, rationale, recommendation, and evidence references. Evidence can be opened directly from the UI; text, JSON, and XML artifacts can be inspected in raw form.

Reports are built from persisted data without re-running scanners. Current exports are:

- self-contained HTML;
- JSON `audit-report` v1;
- Markdown.

PDF is not implemented yet.

## Dashboard, pipeline, and audit diff

The UI now includes an additional WireScope overview that shows:

- asset and service counts;
- findings by severity;
- the current `passive → discovery → protocol → findings → report` pipeline;
- device classes;
- most common services;
- external-tool availability;
- how many assets are supported by both passive and active sources.

Two persisted audits can be compared. The diff reports added and removed assets, open services, and findings.

## Capabilities

WireScope distinguishes **appliance readiness** from optional provider availability.

Core readiness requires SQLite/migrations, the worker, `dumpcap`, and `tshark`. If `ssh-audit`, `smbclient`, or another optional provider is absent, `/ready` does not fail for the entire appliance. The affected capability is simply reported as unavailable through `/api/v1/capabilities` and the UI.

## Architecture

WireScope is a modular monolith. API and worker are separate processes, but the system is not split into networked microservices.

```text
browser / kiosk
      │
      ▼
FastAPI
      │
      ├── backend/routers/
      ├── auth / network / scope
      ├── audits / jobs
      ├── inventory / correlations
      ├── findings / evidence / reports
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

`backend/app.py` is a small composition root. HTTP routes are grouped by domain under `backend/routers/`.

SQLite runs in WAL mode. Normalized data and artifact metadata stay in the database; PCAPs, Nmap XML, raw stdout/stderr, and generated reports live in the evidence store and are registered by UUID, size, and SHA-256.

See [Architecture](docs/en/ARCHITECTURE.md).

## API

The canonical API is `/api/v1/*`. The old `/api/*` prefix remains as a hidden compatibility alias during migration.

In addition to the audit/job endpoints, v1 includes:

```text
GET /api/v1/capabilities
GET /api/v1/scan-profiles
GET /api/v1/audits/{id}/dashboard
GET /api/v1/audits/{id}/correlations
GET /api/v1/audits/{id}/diff?against={old_id}
GET /api/v1/audits/{id}/findings/{finding_id}/evidence
```

See [API documentation](docs/en/API.md).

## Web interface and bind policy

A normal appliance installation listens on **`0.0.0.0:8000`**. This is intentional: the UI should be reachable through any configured interface on the WireScope host, including Ethernet and Wi‑Fi.

The local kiosk still opens `http://127.0.0.1:8000/` because it runs on the same host.

A deployment that needs tighter exposure can use a firewall, explicitly set `--bind-host 127.0.0.1`, or place TLS/reverse proxy controls in front of the API. Those are deployment policies, not mandatory WireScope defaults.

## Privilege model

`wirescope-api` and `wirescope-worker` do not run as root. Packet-capture privileges belong only to `/usr/bin/dumpcap`:

```text
/usr/bin/dumpcap
root:wireshark
0750
cap_net_admin,cap_net_raw=eip
```

WireScope does not grant Nmap extra capabilities. When raw sockets are unavailable, the provider uses the unprivileged modes that remain available.

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

The normal installer/upgrade entrypoints set `0.0.0.0` automatically. A special deployment may override it:

```bash
sudo ./packaging/install.sh --bind-host 127.0.0.1
```

Main system paths:

```text
/opt/wirescope                  source tree + .venv
/etc/wirescope                  configuration
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             systemd units
```

See [Installation](docs/en/INSTALLATION.md).

## Development and tests

Python 3.11+ is required.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
.venv/bin/pytest
```

The repository also contains a GitHub Actions workflow that runs `compileall` and the default test suite on Python 3.11. `network` and `live_pi` tests remain opt-in.

## Documentation

| Document | Contents |
| --- | --- |
| [API](docs/en/API.md) | `/api/v1`, insights, diff, evidence, auth |
| [Installation](docs/en/INSTALLATION.md) | system/user install, kiosk, bind, TLS, upgrade/rollback |
| [Architecture](docs/en/ARCHITECTURE.md) | modules, data flow, jobs, persistence |
| [Scanning model](docs/en/SCANNING_MODEL.md) | scope, declarative profiles, inventory, protocol audits |
| [Security model](docs/en/SECURITY_MODEL.md) | trust boundaries, auth, evidence, privileges |
| [Findings model](docs/en/FINDINGS_MODEL.md) | rules, severity/confidence, state model |
| [Reporting](docs/en/REPORTING_MODEL.md) | `audit-report` v1, HTML/JSON/Markdown |
| [Operator GUI](docs/en/GUI_MODEL.md) | wizard, pipeline, dashboard, diff, evidence |
| [Development](docs/en/DEVELOPMENT.md) | local run, migrations, tests |
| [Runbook](docs/en/RUNBOOK.md) | operations, diagnostics, backup/restore |

## Not implemented yet

- PDF export;
- a dedicated security audit-log table;
- policy-driven automatic cleanup of old audits/evidence;
- automatic retry for interrupted/terminal jobs;
- a complete release matrix for tshark versions across every supported distribution.
