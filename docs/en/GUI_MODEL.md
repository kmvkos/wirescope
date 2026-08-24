# WireScope operator GUI

[Русский](../GUI_MODEL.md) · **English**

The GUI is the normal operator interface. A regular audit does not require shell access: audit creation, passive capture, scope confirmation, active discovery, protocol audits, findings, evidence, and reports are available from the browser.

The frontend is only a client of the durable API. Closing a tab, reloading the page, or restarting the kiosk does not cancel worker jobs.

## Where the GUI runs

### Local kiosk

Chromium runs on the appliance itself and opens:

```text
http://127.0.0.1:8000/
```

The system kiosk owns `tty1` without a full GNOME/KDE/XFCE desktop. VMware uses Xorg/xinit; suitable hardware may use Cage.

### Remote browser

A normal appliance installation listens on `0.0.0.0:8000`, so the operator may open the UI through any configured WireScope interface:

```text
http://<wirescope-ip>:8000/
```

A deployment may tighten exposure with a firewall, direct TLS, a reverse proxy, or an explicit `--bind-host 127.0.0.1`. Loopback-only operation is a deployment choice rather than the WireScope appliance default.

## Frontend stack

The frontend intentionally remains build-free:

```text
frontend/
├── index.html
├── app.js
├── i18n.js
├── style.css
├── enhancements.js
└── enhancements.css
```

`app.js` contains the established wizard and operational screens. `enhancements.js` is loaded separately and adds operator insights without rewriting the primary audit workflow.

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

Progress and summary views expose the durable pipeline:

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

Stage state is derived from persisted jobs. The browser does not maintain a second pipeline state machine.

## WireScope overview

After successful login, an additional **Overview** panel can inspect any saved audit. The control is hidden on the login screen and follows the existing authenticated-session indicator.

### Overview tab

Shows:

- asset count;
- service count;
- finding count;
- Critical/High counts;
- assets supported by both passive and active sources;
- pipeline state;
- device-class distribution;
- most common open services.

Data comes from:

```text
GET /api/v1/audits/{audit_id}/dashboard
GET /api/v1/audits/{audit_id}/correlations
```

There is no separate dashboard database.

### System tab

Shows external-tool availability and the active scan profiles actually loaded by the backend:

```text
GET /api/v1/capabilities
GET /api/v1/scan-profiles
```

The operator can distinguish a healthy appliance from a missing optional provider such as `ssh-audit` or `smbclient`.

The capability response also exposes the current web listener: bind host/port, TLS, and trust-proxy state.

### Compare tab

Two persisted audits can be compared through:

```text
GET /api/v1/audits/{new_id}/diff?against={old_id}
```

The UI groups:

- added/removed assets;
- added/removed open services;
- added/removed findings.

The backend computes the diff; the frontend only renders it.

### Evidence tab

For each finding, the UI queries registered evidence artifacts:

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
```

Text, JSON, and XML evidence can be inspected inline. Binary artifacts are opened/downloaded separately.

The canonical artifact route is audit-scoped:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

## Device classification

The UI renders device-class hints computed by the inventory layer:

```text
server-like
workstation-like
network-device-like
printer-like
iot-like
unknown
```

Classification remains a confidence-rated inventory hint, not a security finding.

## Roles

Local roles are `auditor` and `viewer`.

| Action | Auditor | Viewer |
| --- | --- | --- |
| Read audits/jobs/inventory/findings/reports | yes | yes |
| Dashboard / diff / capabilities / evidence | yes | yes |
| Change own password | yes | yes |
| Create an audit | yes | no |
| Start/cancel jobs | yes | no |
| Listen / Record | yes | no |
| Change network settings | yes | no |
| Change finding state | yes | no |
| Generate a report | yes | no |

The backend enforces roles independently of button visibility in JavaScript.

## Sessions

After login, the backend issues an HttpOnly cookie. The token is random; SQLite stores a SHA-256 digest. `SameSite=strict` is used, and `Secure` is enabled for direct TLS/trusted-proxy deployments.

The active audit id is kept in `sessionStorage` so a reload can return to progress/summary. This is a browser convenience only; backend/SQLite state remains authoritative.

## Summary / observations / assessment / findings

The GUI keeps these concepts separate:

- **Summary** — compact audit state and pipeline;
- **Observations** — normalized facts from protocol modules;
- **Assessment** — confidence-qualified passive interpretation;
- **Findings** — rule-engine conclusions with severity/recommendation/state.

A passive sensor hit does not automatically become a finding.

## VLAN display

A VLAN ID is shown as observed only when an 802.1Q tag was actually present. Untagged access traffic does not receive an invented VLAN ID. LLDP/CDP native or voice VLAN values remain neighbor metadata.

## Listen / Record

The separate `packet_capture` workflow accepts:

- interface;
- optional BPF/tcpdump filter;
- duration;
- maximum PCAP size.

`dumpcap` runs promiscuously, but promiscuous mode does not cause a switch to mirror all VLAN traffic to the port. The resulting PCAP is stored in the evidence store.

## Network screen

Network configuration is handled through backend `NetworkService` and the `netctl` privilege boundary. Potentially disruptive management-path changes require server-side confirmation and cannot be bypassed by frontend code.

## Reports

The GUI can:

- enqueue report generation for an `auditor`;
- browse report history;
- open HTML;
- export JSON;
- export Markdown.

The Markdown control is added by `enhancements.js` next to the existing JSON export and uses the canonical `/api/v1` export endpoint.

PDF currently returns `422 pdf_not_available`.

## Error handling

The UI distinguishes at least:

- validation error;
- worker not ready;
- optional provider unavailable;
- timeout;
- cancellation;
- partial result;
- authorization/role error;
- network-apply confirmation/failure.

A missing provider must never be presented as a passed check or as “nothing found”.

## Kiosk lifecycle

```text
wirescope-api      survives Chromium restart
wirescope-worker   survives Chromium restart
wirescope-kiosk    may restart independently
```

The screen is a client, not the executor.

## Testing

Core GUI/API contracts are fixture-based. Static regression tests also verify that `enhancements.js/.css` are actually loaded by `index.html`, that evidence URLs remain audit-scoped, and that Markdown export stays integrated. Optional Playwright tests are marked `browser` and skipped when Playwright/Chromium is unavailable. CI compiles Python sources and runs the default `pytest` suite.
