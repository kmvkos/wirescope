# WireScope

[Русский](README.md) · **English**

WireScope is a self-contained network audit appliance for Linux. It can run on a small PC, laptop, server, virtual machine, or ARM64 device and is meant to be used as a dedicated tool for examining an unfamiliar network segment.

The workflow is deliberately conservative: connect WireScope to a network, observe the segment passively, explicitly confirm what may be scanned, then build an inventory, run service-aware checks, evaluate findings, and produce a report. WireScope does not treat every route visible from the host as permission to scan it.

The project targets ordinary Linux distributions: Debian/Ubuntu, Fedora/RHEL/Rocky, and openSUSE on `amd64` or `arm64`. Raspberry Pi is a supported hardware option, not a requirement, and Raspberry Pi OS is not required.

## What WireScope does

A normal audit follows this path:

```text
connect to a network
        ↓
snapshot host and interface state
        ↓
passive packet capture
        ↓
observations: ARP, DHCP, VLAN, LLDP/CDP, STP, IPv6, mDNS, LLMNR, NBNS, SSDP
        ↓
operator confirms the authorized scope
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

There is also a separate **Listen / Record** mode. The operator chooses an interface, optionally supplies a BPF/tcpdump filter, sets time and size limits, and WireScope stores the resulting PCAP as an evidence artifact.

### Passive analysis

A regular audit performs one bounded capture with `dumpcap`, then decodes the PCAP once using `tshark -T ek`. The protocol sensors run in-process after that decode step.

Current passive coverage includes:

- Ethernet/MAC;
- 802.1Q VLAN and QinQ;
- ARP;
- DHCPv4 and DHCPv6;
- LLDP and CDP;
- STP;
- IPv6 RA and Neighbor Discovery;
- mDNS, LLMNR, NBNS;
- SSDP.

WireScope keeps observations separate from assumptions. ARP addresses, for example, can provide a useful grouping hint but are not treated as proof of a subnet mask. If an access port delivers untagged frames, WireScope does not invent a VLAN ID for them.

### Active discovery

Nmap runs only after the operator confirms an authorized scope. API clients provide targets and a scan profile, not arbitrary Nmap flags.

Three profiles are available:

- **Discovery** — fast live-host discovery;
- **Standard** — the normal inventory profile: discovery, TCP top 1000, `-sV`, a curated UDP set, and OS detection when the required privileges already exist;
- **Deep** — full TCP `1-65535`, higher service-version intensity, and an expanded UDP set.

`0.0.0.0/0`, `::/0`, multicast ranges, and uncontrolled expansion of large IPv6 prefixes are rejected. Each profile has a target-count limit.

Active discovery does not use NSE, `-sC`, `vuln`, brute-force, exploit, or DoS scripts.

### Protocol checks

After inventory is built, WireScope dispatches only the modules that match discovered services. The current set includes:

- SSH — `ssh-audit`;
- TLS — `openssl s_client`;
- HTTP/HTTPS — `curl`;
- SMB — `smbclient`;
- DNS — `dig`;
- SNMP — a conservative SNMPv3 noAuth probe;
- LDAP — anonymous base DSE with `ldapsearch`.

These modules do not guess passwords or community strings. `testssl.sh`, Nikto, and Nuclei exist only as `never-default` stubs and are not dispatched by normal profiles.

### Findings and reports

Protocol modules store observations, not ready-made “vulnerabilities”. A separate rule engine evaluates normalized data and creates findings. This keeps a fact such as “the server negotiated this cipher” separate from the interpretation “this cipher is weak”.

A finding records severity, confidence, the affected asset/service, rationale, recommendation, and links to supporting evidence. Findings may be marked `suppressed` or `accepted_risk`; state changes are retained in an audit trail.

Report generation works from persisted data and does not re-run scanners. Current exports are:

- self-contained HTML;
- normalized JSON using the `audit-report` v1 schema.

PDF export is not implemented yet.

## Architecture in one page

WireScope is a modular monolith. The API and worker are separate processes, but the system is intentionally not split into networked microservices.

```text
frontend (HTML/CSS/JS)
        │
        ▼
FastAPI
        │
        ├── auth
        ├── environment / interfaces / network / scope
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

SQLite runs in WAL mode. Normalized application data and artifact metadata stay in the database; larger raw files such as PCAPs, Nmap XML, provider stdout/stderr, and generated HTML/JSON reports live in the evidence store and are registered by UUID, size, and SHA-256.

See [Architecture](docs/en/ARCHITECTURE.md) for the full design.

## Privilege model

`wirescope-api` and `wirescope-worker` are not supposed to run as root.

Only `/usr/bin/dumpcap` receives packet-capture privileges:

```text
wirescope-api / wirescope-worker
        │ unprivileged
        ▼
/usr/bin/dumpcap
root:wireshark, 0750
cap_net_admin,cap_net_raw=eip
```

WireScope does not elevate Nmap. If raw sockets are unavailable, the provider falls back to TCP connect scans and skips features that require those capabilities.

External commands are executed as argument arrays through the common runner. `shell=True` is not used on this path.

See [Security model](docs/en/SECURITY_MODEL.md).

## Operator UI

Operators work through a browser. There are two supported deployment styles:

1. **local kiosk** — Chromium on the appliance itself, normally at `http://127.0.0.1:8000/`;
2. **remote browser** — LAN access through TLS and a reverse proxy.

The kiosk does not require GNOME, KDE, or XFCE. The system kiosk owns `tty1` and starts Chromium through Cage or Xorg/xinit. VMware uses the Xorg path.

Local roles are:

- `auditor` — may start and cancel work, change network settings, manage finding state, and generate reports;
- `viewer` — read-only access.

Sessions use HttpOnly cookies. SQLite stores the SHA-256 digest of the random session token, not the token itself.

## Quick install

The recommended system layout keeps the source checkout in `/opt/wirescope`.

```bash
git clone git@github.com:kmvkos/wirescope.git
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance

sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --with-kiosk \
  --enable-kiosk
```

The clone is intentionally performed without `sudo` above because `sudo git clone` uses root's SSH keys rather than the current user's keys.

The installer runs **from the checkout**; it does not copy the application tree elsewhere. Do not delete or rename that checkout after installation because the systemd units reference it.

Default system-install layout:

```text
/opt/wirescope                  source tree and virtualenv
/etc/wirescope                  configuration
/var/lib/wirescope              SQLite, runtime files, evidence, backups
/etc/systemd/system             system units
```

For Debian/Ubuntu, Fedora/RHEL/Rocky, openSUSE, user systemd, kiosk setup, TLS, upgrade, and rollback, see [Installation](docs/en/INSTALLATION.md).

> Note: the appliance CLI currently defaults `--bind-host` to `0.0.0.0`. The documented autonomous-kiosk and reverse-proxy setups therefore pass `--bind-host 127.0.0.1` explicitly. Exposing plain HTTP on `0.0.0.0:8000` should be a deliberate exception, not the default deployment choice.

## Development

Python 3.11+ is required.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
```

Run API and worker in separate terminals:

```bash
.venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000
.venv/bin/python -m jobs.worker
```

The normal test suite does not touch the live network:

```bash
.venv/bin/pytest
```

Tests marked `network` or `live_pi` are opt-in.

## Documentation

| Document | Contents |
| --- | --- |
| [Installation](docs/en/INSTALLATION.md) | system/user install, kiosk, TLS, distro notes, upgrade/rollback |
| [Architecture](docs/en/ARCHITECTURE.md) | modules, data flow, jobs, persistence, privilege boundaries |
| [Scanning model](docs/en/SCANNING_MODEL.md) | scope, Nmap profiles, inventory, protocol audits |
| [Security model](docs/en/SECURITY_MODEL.md) | trust boundaries, authentication, TLS, evidence, least privilege |
| [Findings model](docs/en/FINDINGS_MODEL.md) | rules, severity/confidence, deduplication, false-positive boundaries |
| [Reporting](docs/en/REPORTING_MODEL.md) | `audit-report` v1, HTML/JSON, evidence references |
| [Operator GUI](docs/en/GUI_MODEL.md) | roles, wizard, listen/record, kiosk/laptop layout |
| [Development](docs/en/DEVELOPMENT.md) | local run, migrations, tests, handler contract |
| [Runbook](docs/en/RUNBOOK.md) | operations, diagnostics, backup/restore, recovery |
| [Implementation plan](docs/en/IMPLEMENTATION_PLAN.md) | M0–M8 history and remaining release work |

## Current state

The `milestone-8-appliance` branch contains the M0–M7 feature set plus the current M8 appliance work: installer, systemd integration, kiosk mode, backup/restore, dependency detection, network configuration, TLS/proxy guidance, and the PCAP listen/record workflow.

Known limitations include:

- no PDF export;
- no dedicated security audit-log table yet;
- no policy-driven automatic deletion of completed audits and registered evidence;
- no automatic retry for terminal/interrupted jobs;
- tshark compatibility still needs release testing against the package versions shipped by each supported distribution.
