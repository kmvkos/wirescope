# WireScope operator GUI

[Русский](../GUI_MODEL.md) · **English**

The GUI is the normal operator interface. A regular audit does not require shell access: audit creation, passive capture, scope confirmation, active discovery, protocol audits, findings, evidence, reports, Traffic Analysis, Network Topology, and first-line appliance diagnostics are available from the browser.

The frontend is a client of durable API state. Closing a tab, reloading the page, or restarting the kiosk does not cancel worker jobs.

## Where the GUI runs

The local kiosk opens:

```text
http://127.0.0.1:8000/
```

A normal appliance installation listens on `0.0.0.0:8000`, so a remote operator can open the GUI through any configured WireScope interface address.

## Frontend and visual layer

The frontend intentionally remains build-free. The primary wizard lives in `frontend/app.js`; additional functions are split into dedicated modules.

Topology uses dedicated presentation modules over the canonical API. The browser is not the source of truth: topology, jobs, inventory, findings, and evidence are derived from backend/SQLite/evidence state.

The root page uses `Cache-Control: no-store`, and CSS/JS URLs carry version query strings. This is especially important for the topology renderer so Chromium does not keep stale JS/CSS after upgrade.

`packaging/upgrade.sh` restarts the kiosk browser after a successful upgrade when kiosk mode is enabled; API/worker jobs remain durable.

## Main audit flow

```text
login
  ↓
home
  ↓
new audit
  ↓
environment / interface
  ↓
network + scope
  ↓
profile
  ↓
confirmation
  ↓
passive → discovery → protocol → findings → report
  ↓
summary / inventory / evidence / traffic / topology
```

Pipeline state is derived from durable jobs in SQLite. The browser does not maintain another audit state machine.

## Overview panel

After login, the operator can select a retained audit and open different views.

### Overview

Shows assets, services, findings, Critical/High counts, passive+active correlation, pipeline, device classes, and common services.

```text
GET /api/v1/audits/{audit_id}/dashboard
GET /api/v1/audits/{audit_id}/correlations
```

### System

Shows runtime capabilities, listener state, and scan profiles:

```text
GET /api/v1/capabilities
GET /api/v1/scan-profiles
```

A missing optional provider appears as an unavailable capability rather than a successful check.

### Compare

```text
GET /api/v1/audits/{new_id}/diff?against={old_id}
```

The UI groups added/removed assets, open services, and findings.

### Evidence

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Text/JSON/XML evidence is rendered inline; binary artifacts are opened separately. Artifact access is always audit-scoped.

## Network Topology workspace

Topology is a dedicated operator workspace rather than a decorative inventory view.

Primary endpoint:

```text
GET /api/v1/audits/{audit_id}/topology
```

An explicitly selected PCAP overlay is attached with `traffic_analysis_job_id`. WireScope never chooses the “latest capture” automatically.

### Views

Available views include:

- **Structural** — the primary infrastructure-first diagram;
- **L2** — evidence-backed physical/adjacency/port relationships;
- **L3** — subnet/gateway/router/interface relationships;
- **Traffic** — communications from the selected Traffic Analysis result;
- **All Evidence** — expanded technical canonical-graph view;
- **VLAN Focus** — evidence-backed VLAN/port context;
- **Topology History** — comparison of two retained audits.

Structural view deliberately reduces noise: subnet-directed broadcast, uncorrelated link-local endpoints, and PCAP-only external addresses should not look like ordinary infrastructure hosts.

### Coverage / evidence sufficiency

The UI renders `coverage` for:

```text
inventory
l3
l2
traffic
vlan
wifi
hypervisor
```

Statuses are:

```text
sufficient
partial
missing
```

This is not a “percentage of the network discovered.” `missing` means WireScope has insufficient evidence for that class of claim. The UI should show what evidence is missing instead of hiding the limitation.

### Topology controls

Supported controls include zoom, pan, fit, subnet focus, confidence filters, asset details, edge details, findings on assets, explicit Traffic overlay, and global retained-audit topology.

### Export

Available exports include:

- canonical topology JSON;
- full structural SVG diagram;
- structural PNG diagram;
- current viewport SVG;
- VLAN JSON/SVG;
- topology diff JSON.

Full-diagram export is independent of the current viewport and is intended to produce a readable export of the whole structural map.

### Management enrichment

Auditors can launch optional read-only enrichment:

```text
POST /api/v1/audits/{audit_id}/topology/snmp
POST /api/v1/audits/{audit_id}/topology/ssh
```

The target must remain inside confirmed scope.

The SNMP form accepts read-only v2c/v3 credentials.

The SSH form targets Linux/OpenWrt-like managed devices, requires verified host-key material, and does not allow arbitrary remote commands. Credential material must not be displayed after submission and is not retained as plaintext topology evidence.

If a MIB/SSH capability is unavailable, the UI shows partial/missing evidence rather than a synthetic topology.

See [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md).

## Traffic Analysis

A separate `packet_capture` workflow saves PCAP. The operator can then start deterministic Traffic Analysis without another capture.

Traffic Analysis and Network Topology are related but distinct views: the first answers “what communication was visible at this capture point,” while topology answers “which structural/network relationships are supported by evidence.”

## Operations

The Operations tab is auditor-only and exposes runtime readiness, SQLite `quick_check`, worker/core tools, disk/evidence usage, retention policy, retryable jobs, recent operational events, and diagnostics export.

Cleanup is two-step: preview does not delete anything; actual cleanup requires explicit confirmation.

Generic retry creates a new durable job. Credentialed SNMP/SSH topology jobs cannot be retried with old credential references; enrichment is launched again with fresh credentials.

## Device classification

The UI displays inventory classification:

```text
server-like
workstation-like
network-device-like
printer-like
iot-like
unknown
```

Classification is a confidence-rated inventory hint, not a finding.

## Roles

| Action | Auditor | Viewer |
| --- | --- | --- |
| Read audits/jobs/inventory/findings/reports/topology | yes | yes |
| Dashboard / diff / capabilities / evidence | yes | yes |
| View topology/traffic/history | yes | yes |
| Change own password | yes | yes |
| Create an audit | yes | no |
| Start/cancel jobs | yes | no |
| Listen / Record | yes | no |
| SNMP/SSH topology enrichment | yes | no |
| Change network settings | yes | no |
| Change finding state | yes | no |
| Generate a report | yes | no |
| Diagnostics / audit log / maintenance | yes | no |

Backend authorization is enforced independently of button visibility.

## Sessions

After login, the backend issues an HttpOnly cookie. SQLite stores only a SHA-256 token digest. `SameSite=strict` is used; `Secure` is enabled for direct TLS/trusted-proxy deployments.

The active audit id may be stored in `sessionStorage` only as a UI convenience. Backend state remains authoritative.

## VLAN display

A passive VLAN ID is considered observed only when an actual 802.1Q tag was present.

Topology can additionally establish VLAN membership from FDB/Q-BRIDGE/management evidence. A trunk/hybrid port without an exact endpoint VLAN never forces the UI to choose one arbitrary VLAN.

## Network screen

Network configuration goes through backend `NetworkService` and the `netctl` privilege boundary. Potentially disruptive management-path changes require server-side confirmation.

## Reports

The GUI opens human-readable HTML and exports canonical JSON/Markdown. Reports are built from persisted data and do not start a new network audit.

## Errors and recovery

The GUI distinguishes validation, provider, timeout, cancellation, authorization, and network errors.

Topology additionally exposes `partial`, `source_errors`, and `coverage` so the loss of one management artifact cannot masquerade as a complete map.

## Kiosk lifecycle

```text
wirescope-api      survives Chromium restart
wirescope-worker   survives Chromium restart
wirescope-kiosk    may restart independently
```

The screen is a client, not the executor.

## Testing

CI covers compileall, the default pytest suite, Chromium regression, wheel build, and installed-wheel smoke.

Topology browser regression covers structural rendering, filters, zoom/focus, bounded layout, findings, exports, and VLAN focus. M11.4 live smoke was completed on an upgraded WireScope VM; vendor-specific SNMP/SSH interoperability remains additional validation when suitable managed devices are available.