# WireScope

[Русский](README.md) · **English**

WireScope is a self-contained network audit appliance for Linux. It can run on a small PC, laptop, server, virtual machine, or ARM64 device and is intended as a dedicated tool for examining an unfamiliar network segment.

The workflow is conservative by design: observe the network passively first, explicitly define what may be scanned, build an inventory, run checks that match discovered services, and produce a technical report. WireScope does not treat every route reachable from the host as automatically authorized scope.

The target platform is ordinary Linux: Debian/Ubuntu, Fedora/RHEL/Rocky, and openSUSE on `amd64` and `arm64`. Raspberry Pi is one supported hardware option, not a requirement, and Raspberry Pi OS is not required.

## Audit workflow

```text
connect to a network
        ↓
snapshot host and interface state
        ↓
passive packet capture
        ↓
ARP / DHCP / VLAN / LLDP / CDP / STP / IPv6 / naming protocols
        ↓
operator confirms authorized scope
        ↓
active discovery with Nmap
        ↓
asset and service inventory
        ↓
service-aware protocol checks
        ↓
findings
        ↓
HTML / JSON report
```

A separate **Listen / Record** mode lets the operator select an interface, optionally provide a BPF/tcpdump filter, set time and file-size limits, and retain the resulting PCAP as an evidence artifact.

### Passive analysis

A normal audit performs one bounded capture with `dumpcap`, then decodes the PCAP once with `tshark -T ek`. Sensors operate on normalized packet records inside the Python process.

Current coverage includes Ethernet/MAC, 802.1Q/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS, and SSDP.

Observations stay separate from assumptions. ARP addresses, for example, may provide a useful grouping hint but are not proof of the actual subnet mask. If an access port delivers untagged frames, WireScope does not invent a VLAN ID.

### Active discovery

Nmap runs only after scope confirmation. Clients submit targets and a profile, not arbitrary Nmap flags.

Profiles:

- **Discovery** — fast live-host discovery;
- **Standard** — normal inventory: host discovery, TCP top 1000, `-sV`, a curated UDP set, and OS detection when the required privileges already exist;
- **Deep** — TCP `1-65535`, deeper service identification, and an expanded UDP set.

`0.0.0.0/0`, `::/0`, multicast ranges, and uncontrolled expansion of large IPv6 prefixes are rejected. Discovery does not use NSE, `-sC`, `vuln`, brute-force, exploit, or DoS scripts.

### Protocol checks

After inventory is built, WireScope runs only modules that match discovered services:

- SSH — `ssh-audit`;
- TLS — `openssl s_client`;
- HTTP/HTTPS — `curl`;
- SMB — `smbclient`;
- DNS — `dig`;
- SNMP — a conservative SNMPv3 noAuth probe;
- LDAP — anonymous base DSE with `ldapsearch`.

The modules do not guess passwords or community strings. `testssl.sh`, Nikto, and Nuclei remain `never-default` and are not dispatched by normal profiles.

### Findings and reports

Protocol modules persist facts. A separate rule engine evaluates normalized observations and creates findings, keeping a fact such as “the server offered this cipher” separate from the interpretation “this cipher is weak”.

A finding records severity, confidence, affected asset/service, rationale, recommendation, and links to evidence. `suppressed` and `accepted_risk` states retain their change history.

Report generation uses persisted data and does not re-run scanners. Current outputs are self-contained HTML and normalized JSON using the `audit-report` v1 schema. PDF is not implemented yet.

## Architecture

WireScope remains a modular monolith. API and worker are separate processes, but they are not networked microservices.

```text
frontend (HTML/CSS/JS)
        │
        ▼
FastAPI
        │
        ├── backend/routers/
        ├── auth / network / scope
        ├── audits / jobs
        ├── inventory
        ├── findings / reports
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

`backend/app.py` is the composition root: it constructs services and attaches API routers, the frontend, and static files. HTTP routes are grouped by domain under `backend/routers/`.

SQLite runs in WAL mode. Normalized data and artifact metadata live in the database; PCAPs, Nmap XML, raw provider stdout/stderr, and generated reports live in the evidence store and are registered by UUID, size, and SHA-256.

See [Architecture](docs/en/ARCHITECTURE.md).

## HTTP API

The canonical API is under `/api/v1`:

```text
GET  /api/v1/health
GET  /api/v1/environment
POST /api/v1/audits
GET  /api/v1/jobs/{job_id}
```

The old `/api/*` prefix is temporarily retained as a compatibility alias, so the current frontend and existing clients continue to work. Legacy routes are hidden from OpenAPI; Swagger/ReDoc expose only `/api/v1/*`.

See [docs/en/API.md](docs/en/API.md).

## Privilege model

`wirescope-api` and `wirescope-worker` are not supposed to run as root. Packet-capture privileges belong only to `/usr/bin/dumpcap`:

```text
wirescope-api / wirescope-worker
        │ unprivileged
        ▼
/usr/bin/dumpcap
root:wireshark, 0750
cap_net_admin,cap_net_raw=eip
```

WireScope does not elevate Nmap. If raw sockets are unavailable, the provider uses TCP connect scanning and skips features that require those capabilities.

External commands are executed as argument arrays through the common runner; `shell=True` is not used on this path.

See [Security model](docs/en/SECURITY_MODEL.md).

## Operator UI

Operators use a browser. Two main deployment modes are supported:

1. **local kiosk** — Chromium on the appliance itself, normally `http://127.0.0.1:8000/`;
2. **remote browser** — LAN access through TLS and a reverse proxy.

The kiosk does not require GNOME, KDE, or XFCE. The system kiosk owns `tty1` and starts Chromium through Cage or Xorg/xinit; VMware uses the Xorg path.

Roles:

- `auditor` — start/cancel jobs, change network settings, manage finding state, generate reports;
- `viewer` — read-only access.

Sessions use an HttpOnly cookie. SQLite stores the SHA-256 digest of the token rather than the token itself.

## Quick install

The recommended system layout keeps the checkout in `/opt/wirescope`.

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

Clone without `sudo` so Git uses the current user's SSH keys. Checkout before moving the repository into `/opt` to avoid unnecessary ownership and `safe.directory` issues.

The installer runs **from the checkout** and does not copy application code elsewhere. Do not remove or rename the checkout after installation because systemd units reference it.

Both installer and application defaults bind to **`127.0.0.1:8000`**. A public bind must be explicit:

```bash
sudo ./packaging/install.sh --bind-host 0.0.0.0
```

For access from another machine, the preferred deployment keeps the API on loopback and puts Caddy or nginx with TLS in front of it.

Default system-install layout:

```text
/opt/wirescope                  source tree and virtualenv
/etc/wirescope                  configuration
/var/lib/wirescope              SQLite, runtime files, evidence, backups
/etc/systemd/system             system units
```

See [Installation](docs/en/INSTALLATION.md) for distro-specific setup, user systemd, kiosk mode, TLS, upgrade, and rollback.

## Development

Python 3.11+ is required.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
```

Run API and worker separately:

```bash
.venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000
.venv/bin/python -m jobs.worker
```

The normal test suite does not contact a live network:

```bash
.venv/bin/pytest
```

`network` and `live_pi` tests are opt-in.

## Documentation

| Document | Contents |
| --- | --- |
| [API](docs/en/API.md) | `/api/v1`, compatibility policy, authorization semantics |
| [Installation](docs/en/INSTALLATION.md) | system/user install, kiosk, TLS, distro notes, upgrade/rollback |
| [Architecture](docs/en/ARCHITECTURE.md) | modules, data flow, jobs, persistence, privilege boundaries |
| [Scanning model](docs/en/SCANNING_MODEL.md) | scope, Nmap profiles, inventory, protocol audits |
| [Security model](docs/en/SECURITY_MODEL.md) | trust boundaries, auth, TLS, evidence, least privilege |
| [Findings model](docs/en/FINDINGS_MODEL.md) | rules, severity/confidence, deduplication, false-positive boundaries |
| [Reporting](docs/en/REPORTING_MODEL.md) | `audit-report` v1, HTML/JSON, evidence references |
| [Operator GUI](docs/en/GUI_MODEL.md) | roles, wizard, listen/record, kiosk/laptop layout |
| [Development](docs/en/DEVELOPMENT.md) | local run, migrations, tests, handler contract |
| [Runbook](docs/en/RUNBOOK.md) | operations, diagnostics, backup/restore, recovery |
| [Implementation plan](docs/en/IMPLEMENTATION_PLAN.md) | M0–M8 history and remaining work |

## Current state

The appliance line contains the M0–M7 feature set plus the current M8 work: installer, systemd integration, kiosk mode, backup/restore, dependency detection, network configuration, TLS/proxy support, and PCAP listen/record.

Known limitations include:

- no PDF export yet;
- no dedicated security audit-log table yet;
- no policy-driven automatic deletion of completed audits and registered evidence;
- no automatic retry for terminal/interrupted jobs;
- tshark compatibility still needs release testing against the package versions shipped by supported distributions.
