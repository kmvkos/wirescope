# WireScope v1.0 readiness

[Русский](../RELEASE_READINESS.md) · **English**

WireScope needs a point where development stops being judged by “there is still another feature we could add” and starts being judged as a product. For the first stable release, that point is **WireScope v1.0 RC1**.

RC1 does not mean that no more protocol modules, report formats, or topology views will ever be added. It means the core audit workflow and appliance lifecycle are predictable enough to use WireScope as an operational tool rather than a lab prototype.

## Release gate

WireScope may be tagged `v1.0.0-rc1` only when every mandatory gate below passes.

### 1. Install and upgrade

- clean installation succeeds on a supported Linux system;
- upgrading an existing installation applies Alembic migrations without losing audits or evidence;
- API and worker start after install and upgrade;
- `0.0.0.0:8000` remains the normal default listener;
- the GUI is reachable through the IP address of any configured appliance interface;
- the local kiosk may still open `127.0.0.1:8000`;
- `dumpcap` remains the packet-capture privilege boundary and API/worker remain unprivileged.

### 2. Data integrity

- SQLite opens successfully;
- the Alembic revision is current;
- `PRAGMA quick_check` returns `ok`;
- the appliance backup command produces a usable backup;
- restore passes `integrity_check` and restores the database/evidence state;
- restarting API/worker does not corrupt completed audits.

### 3. Authentication and roles

- an auditor can perform mutating operations;
- a viewer can read results but cannot start/cancel jobs or change appliance state;
- login, logout and password changes work after upgrade;
- the session cookie is not readable from JavaScript;
- passwords and session tokens never enter the operational audit log.

### 4. Full audit workflow

A real test segment must complete:

```text
login
  ↓
interface selection
  ↓
passive capture
  ↓
scope confirmation
  ↓
active discovery
  ↓
protocol audits
  ↓
findings
  ↓
report
```

Required behavior:

- passive capture produces observations/inventory when traffic is available;
- active discovery never leaves the confirmed scope;
- a missing optional provider is reported as `unavailable`, never as a passed check;
- failed, timed-out or cancelled jobs are not presented as successful;
- inventory, findings and reports survive browser reloads.

### 5. Audit outputs

Verify:

- asset inventory;
- services;
- device classification with confidence;
- passive/active correlation;
- findings and evidence;
- HTML report;
- JSON report;
- Markdown report;
- audit-to-audit diff.

A VLAN ID is treated as directly observed only when an 802.1Q tag was present. Untagged traffic must never receive an invented VLAN ID.

### 6. Recovery

After forcing a worker restart during a job:

- the job becomes `interrupted`;
- resource locks are released;
- the audit does not remain permanently `running`;
- the operator can explicitly retry an interrupted, failed or cancelled stage;
- retry creates a new durable job instead of rewriting the old job history;
- already completed stages do not need to be repeated unless required.

WireScope does not attempt to resume an Nmap process from an arbitrary internal position. Recovery is stage-level and durable.

### 7. Lifecycle and disk usage

Diagnostics must show:

- SQLite state;
- migration state;
- worker readiness;
- core tool readiness;
- free disk space;
- evidence-store size;
- retention policy.

Cleanup must remain conservative:

- preview mode never deletes files;
- raw evidence deletion requires explicit confirmation;
- safe housekeeping may remove stale temporary/orphan data;
- normalized inventory, findings and reports are not automatically deleted;
- expiring old PCAP/Nmap XML/protocol raw output must not erase normalized audit history.

Default policy:

| Data | Default |
| --- | ---: |
| Temporary artifacts | 24 hours |
| Debug artifacts | 7 days |
| PCAP | 30 days |
| Nmap XML / protocol raw evidence | 90 days |
| Normalized audit history | no automatic deletion |

The policy can be changed through environment variables without changing code.

### 8. Operational audit log

At minimum, record:

- successful and failed login;
- logout;
- password change;
- audit creation;
- passive/active/protocol starts;
- job cancel/retry;
- network changes;
- finding-state changes;
- report generation;
- maintenance cleanup.

Records contain time, actor, role, action, HTTP status and client IP. Request bodies, passwords, cookies and provider stdout are not copied into this log.

### 9. Diagnostics

`GET /api/v1/diagnostics` must provide enough state to begin troubleshooting without SSH:

- product version, platform and Python;
- bind/TLS/proxy state;
- runtime checks;
- capabilities;
- database quick-check;
- disk/evidence usage;
- retention candidates;
- recent operational events.

`/api/v1/diagnostics/export` exports the same safe snapshot as JSON.

### 10. CI

Before RC1, the final candidate must pass:

```bash
python -m compileall ...
pytest
```

A green build achieved by disabling failing regression tests does not satisfy the gate.

### 11. Live appliance smoke test

CI does not replace the appliance. The last mandatory gate is performed on an installed WireScope VM or host after upgrade.

Minimum sequence:

1. update the checkout;
2. run the supported `packaging/upgrade.sh` path;
3. verify migration head;
4. restart API/worker;
5. open the GUI from another host through a WireScope interface address;
6. verify login;
7. inspect Capabilities and Diagnostics;
8. run a passive audit;
9. run a Standard audit against an authorized test scope;
10. inspect assets/services/findings/evidence;
11. open HTML and download JSON/Markdown reports;
12. run a second audit and inspect diff;
13. interrupt one job by restarting the worker and verify retry;
14. run retention preview;
15. create a backup.

Only then should the candidate receive:

```text
v1.0.0-rc1
```

## When the product is “ready”

After the RC1 smoke test succeeds, WireScope can reasonably be considered **mature enough for regular use in controlled network auditing**.

Before tagging final `v1.0.0`, it is preferable to run several real audits on different segments and confirm that there are no release-blocking installation, persistence, scope-control, or reporting defects. New feature ideas alone do not block 1.0.

## Not release blockers for v1.0

Useful post-1.0 work includes:

- PDF export;
- React/Vue or another frontend framework;
- PostgreSQL/Redis/Celery;
- microservices;
- topology graph;
- CVE enrichment;
- scheduled audits;
- deeper historical identity correlation;
- FTP/SMTP/RDP/Redis/database/MQTT/VNC and other additional protocol modules;
- removing the compatible `/api/*` alias completely;
- automatic deletion of all historical audits.

These belong to the post-1.0 roadmap and must not move the finish line indefinitely.
