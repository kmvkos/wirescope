# WireScope operator GUI

[Русский](../GUI_MODEL.md) · **English**

The GUI is the normal operator interface. A regular audit does not require shell access: audit creation, passive capture, scope confirmation, active discovery, protocol audits, findings, evidence, reports, and first-line appliance diagnostics are available from the browser.

The frontend is a client of durable API state. Closing a tab, reloading the page, or restarting the kiosk does not cancel worker jobs.

## Where the GUI runs

The local kiosk opens:

```text
http://127.0.0.1:8000/
```

A normal appliance installation listens on `0.0.0.0:8000`, so a remote operator may open the GUI through any configured WireScope interface address.

## Frontend stack

The frontend intentionally remains build-free:

```text
frontend/
├── index.html
├── app.js
├── i18n.js
├── style.css
├── enhancements.js
├── enhancements.css
└── operations.js
```

`app.js` contains the primary wizard. `enhancements.js` adds dashboard/diff/evidence/Markdown functionality. `operations.js` separately adds lifecycle controls for auditors.

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
summary / inventory / evidence / report
```

## Pipeline

Progress and summary expose the durable pipeline:

```text
Passive analysis
      ↓
Discovery
      ↓
Protocol checks
      ↓
Findings
      ↓
Report
```

Stage state is derived from jobs in SQLite. The browser does not maintain another pipeline state machine.

## Overview panel

After successful login, the panel can inspect any persisted audit. The control is hidden on the login screen.

### Overview

Shows asset/service counts, findings, Critical/High counts, passive+active correlation, pipeline, device classes, and common services.

```text
GET /api/v1/audits/{audit_id}/dashboard
GET /api/v1/audits/{audit_id}/correlations
```

### System

Shows runtime capabilities, the effective listener, and loaded scan profiles:

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

### Operations

This tab is visible only to `auditor` and is implemented by `operations.js`.

It uses:

```text
GET  /api/v1/diagnostics
GET  /api/v1/diagnostics/export
GET  /api/v1/audits/{audit_id}/jobs
POST /api/v1/jobs/{job_id}/retry
POST /api/v1/maintenance/cleanup
```

It shows:

- runtime ready/not-ready;
- SQLite `quick_check`;
- worker/core-tool state;
- free disk space;
- evidence-store usage;
- retention policy and cleanup candidates;
- failed/interrupted/cancelled jobs for the selected audit;
- recent operational events.

Cleanup is deliberately two-step. **Preview cleanup** sends `confirm=false`. Actual raw-evidence deletion requires a browser confirmation and `confirm=true`.

Retry creates a new durable job and keeps the terminal source job immutable.

## Device classification

The UI renders the classification produced by inventory:

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
| Read audits/jobs/inventory/findings/reports | yes | yes |
| Dashboard / diff / capabilities / evidence | yes | yes |
| Change own password | yes | yes |
| Create an audit | yes | no |
| Start/cancel jobs | yes | no |
| Retry terminal job | yes | no |
| Listen / Record | yes | no |
| Change network settings | yes | no |
| Change finding state | yes | no |
| Generate a report | yes | no |
| Diagnostics / audit log / maintenance | yes | no |

The backend enforces roles independently of button visibility.

## Sessions

After login, the backend issues an HttpOnly cookie. SQLite stores only a SHA-256 token digest. `SameSite=strict` is used; `Secure` is enabled for direct TLS/trusted-proxy deployments.

The active audit id in `sessionStorage` is a UI convenience for reload recovery. Backend/SQLite remains authoritative.

## Summary / observations / assessment / findings

- **Summary** — compact audit/pipeline state;
- **Observations** — normalized sensor/protocol facts;
- **Assessment** — confidence-rated passive interpretation;
- **Findings** — rule-engine conclusions with severity/recommendation/state.

A passive sensor hit does not automatically become a finding.

## VLAN display

A VLAN ID is shown as observed only when an 802.1Q tag was present. Untagged access traffic does not receive an invented VLAN ID. LLDP/CDP native or voice VLAN remains neighbor metadata.

## Listen / Record

The separate `packet_capture` workflow accepts interface, optional BPF/tcpdump filter, duration, and maximum PCAP size. Promiscuous mode records frames received by the NIC; it does not turn a switch port into SPAN.

## Network screen

Network configuration goes through backend `NetworkService` and the `netctl` privilege boundary. Potentially disruptive management-path changes require server-side confirmation.

## Reports

The GUI opens HTML and exports JSON/Markdown. The Markdown control is added by `enhancements.js` and uses the canonical `/api/v1` export route. PDF returns `422 pdf_not_available` and does not block v1.0.

## Error handling and recovery

The UI distinguishes validation, provider, timeout, cancellation, authorization, and network errors. An auditor may explicitly retry a failed/interrupted/cancelled stage through Operations. There is no uncontrolled automatic retry loop.

## Kiosk lifecycle

```text
wirescope-api      survives Chromium restart
wirescope-worker   survives Chromium restart
wirescope-kiosk    may restart independently
```

The screen is a client, not the executor.

## Testing

Fixture/API tests cover roles and workflow. Static regression tests verify enhancement-module loading, audit-scoped evidence, Markdown export, and the operations lifecycle UI. Optional Playwright tests retain the `browser` marker. CI runs compileall and the default pytest suite.

The release checklist is in [RELEASE_READINESS.md](RELEASE_READINESS.md).
