# WireScope development roadmap

[Русский](../IMPLEMENTATION_PLAN.md) · **English**

This document records the major architectural stages and the current roadmap. Current behavior is documented in [ARCHITECTURE.md](ARCHITECTURE.md), appliance lifecycle in [OPERATIONS.md](OPERATIONS.md), and the first stable release boundary in [RELEASE_READINESS.md](RELEASE_READINESS.md).

## Project status

```text
M0  prototype stabilization               complete
M1  passive foundation                    complete
M2  durable jobs + persistence            complete
M3  active discovery                      complete
M4  service-aware protocol audits         complete
M5  findings engine                       complete
M6  reporting                             complete
M7  operator GUI + local auth             complete
M8  generic Linux appliance               implementation complete
M9  hardening + lifecycle                 implementation complete / release validation pending

                                      ↓
                             v1.0.0-rc1 release gate
```

The current goal is **not to add scanners indefinitely**. It is to validate the existing appliance as a release candidate.

## Non-negotiable project rules

- Python 3.11+;
- generic Linux on `amd64`/`arm64`;
- API and worker remain unprivileged;
- external tools use argv arrays and no `shell=True`;
- packet-capture privileges belong only to `dumpcap`;
- active scans stay inside operator-confirmed scope;
- raw evidence stays separate from normalized data;
- provider/parser failure never means protocol absence;
- runtime behavior requires tests and documentation;
- default pytest must not accidentally use a live network.

---

# M0 — Stabilize — complete

The prototype became a reproducible Python codebase: centralized settings, `pyproject.toml`, virtualenv/dependency setup, initial API/environment/sensor tests, architecture boundaries, and a roadmap.

---

# M1 — Passive foundation — complete

A bounded passive pipeline was established:

```text
validated interface
      ↓
dumpcap → PCAP
      ↓
tshark -T ek
      ↓
PacketRecord
      ↓
sensors
      ↓
assessment
```

Coverage includes Ethernet/MAC, VLAN/QinQ, ARP, DHCPv4/v6, LLDP/CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS, SSDP, and confidence-aware assessment.

---

# M2 — Durable jobs + persistence — complete

Process-local state was replaced by SQLite as the system of record.

Added:

- SQLAlchemy/Alembic;
- WAL/foreign keys/busy timeout;
- `queued/running/completed/failed/cancelled/interrupted`;
- API/worker split;
- job events;
- worker heartbeat;
- resource locks;
- restart recovery;
- atomic artifact storage.

---

# M3 — Active discovery — complete

WireScope gained confirmed active scope and a controlled Nmap provider.

Before execution it validates/canonicalizes targets, enforces scope caps, rejects unspecified/multicast targets, revalidates interface/route, and persists an immutable confirmed-scope snapshot.

Nmap XML is evidence; assets/services are normalized inventory. Identity correlation prefers MAC then IP and preserves conflicts rather than aggressively merging devices.

---

# M4 — Service-aware protocol audits — complete

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

A module runs only for a matching discovered service inside authorized scope. Credential guessing and aggressive vulnerability scanners are not default behavior.

---

# M5 — Findings — complete

```text
normalized observations
        ↓
versioned rules
        ↓
findings
```

Findings gained severity, confidence, evidence links, recommendations, deduplication, and state history such as suppressed/accepted-risk.

---

# M6 — Reporting — complete

Canonical report contract:

```text
audit-report v1
```

JSON and self-contained HTML were introduced first; Markdown was later added over the same persisted contract. Report generation does not contact the network.

---

# M7 — GUI + local auth — complete

The product became browser-first:

```text
login → audit wizard → progress → inventory/findings → report
```

Added auditor/viewer roles, local sessions, kiosk layout, durable polling, network screen, Listen/Record, and password change.

---

# M8 — Generic Linux appliance — implementation complete

M8 turned the Python project into an installable appliance.

Implemented:

- apt/dnf/yum/zypper detection;
- amd64/arm64;
- system and user install;
- service account;
- `/opt/wirescope`, `/etc/wirescope`, `/var/lib/wirescope` layout;
- dumpcap least privilege;
- API/worker/kiosk systemd units;
- tty1 Chromium kiosk without a full desktop;
- network helper;
- backup/restore;
- upgrade path;
- direct TLS/reverse-proxy helpers;
- dependency inventory/checksums;
- `0.0.0.0:8000` as the normal appliance listener.

Cross-distro and real-hardware checks are release validation rather than a reason to keep M8 permanently open.

---

# M9 — Hardening & lifecycle — implementation complete

M9 is the final mandatory code milestone before RC1.

## API structure

The former large `backend/app.py` was decomposed into domain routers. `/api/v1` is canonical; `/api` remains a temporary compatibility alias.

## Operator insights

Added runtime capabilities, declarative active profiles, dashboard/pipeline, passive/active correlation view, stronger device classification, audit diff, audit-scoped evidence, and Markdown export.

## Operational audit log

`operational_events` records significant operator mutations and login attempts without storing request bodies or secrets.

## Recovery

Manual retry for failed/interrupted/cancelled jobs creates a new durable job. Terminal history stays immutable; recovery operates at stage level.

## Lifecycle / retention

The lifecycle service provides SQLite quick-check, disk/evidence usage, retention candidates, preview-first cleanup, explicit raw-evidence deletion, and preservation of normalized audit history.

## Diagnostics

Auditors get a single diagnostic snapshot and JSON export before needing SSH.

## Operations UI

`frontend/operations.js` exposes health, disk usage, retention, operational events, and retry controls without expanding the primary wizard.

## CI

GitHub Actions compiles Python and runs the default pytest suite. Regression coverage now includes API versioning, profiles, insights, evidence, Markdown, bind policy, lifecycle/retry/diagnostics, and frontend integration.

---

# v1.0 RC1 — release gate

**RC1 is the next milestone, but it is not another feature milestone.** It cannot be closed by a GitHub commit alone.

Required live path:

```text
backup
  ↓
git update + packaging/upgrade.sh
  ↓
migrations current
  ↓
API + worker ready
  ↓
remote GUI through appliance IP
  ↓
passive audit
  ↓
Standard audit on authorized scope
  ↓
assets/services/findings/evidence
  ↓
HTML/JSON/Markdown
  ↓
second audit + diff
  ↓
worker interruption + retry
  ↓
retention preview
  ↓
diagnostics / operational log
```

Full gate: [RELEASE_READINESS.md](RELEASE_READINESS.md).

After it passes:

```text
v1.0.0-rc1
```

After several real audits with no release-blocking install, persistence, scope-control, or reporting defects, the project can move to `v1.0.0`.

---

# Post-1.0 roadmap

These items are useful but **do not block the first stable release**.

## Protocol coverage

Candidates include FTP, SMTP, RDP, Redis, PostgreSQL/MySQL/MSSQL, MongoDB, Elasticsearch, MQTT, UPnP, IPMI, NTP, TFTP, Telnet, VNC, Docker API, and Kubernetes API.

Each requires a safe observation contract before finding rules.

## Reports

- PDF renderer over `audit-report v1`;
- additional exports only when real workflows require them.

## Network intelligence

- topology graph;
- deeper historical identity tracking;
- CVE enrichment;
- scheduled/baseline audits.

## Engineering

- further frontend decomposition;
- eventual removal of `/api/*` alias;
- broader distro/architecture CI matrix;
- a credential security model if authenticated checks are introduced.

## Definition of done for future runtime changes

A change is complete when it has implementation, migration if required, unit/fixture/API coverage, explicit failure behavior, timeout/cancellation for external tools, no secrets in logs/units, updated documentation, and green default CI.

The enduring rule is simple: WireScope must do what it tells the operator it is doing and must never turn missing evidence into an overconfident conclusion.
