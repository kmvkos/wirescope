# WireScope operator GUI

[Русский](../GUI_MODEL.md) · **English**

The GUI is the normal operator interface. A regular audit does not require shell access: audit creation, passive capture, scope confirmation, active discovery, protocol audits, findings, and report generation are available from the browser.

The frontend is a client of the durable API. It does not own worker-job lifetime: closing the tab, reloading the page, or restarting the kiosk does not cancel running work.

## Where the GUI runs

Two modes are supported.

### Local kiosk

Chromium runs on the WireScope appliance itself:

```text
http://127.0.0.1:8000/
```

No management network to another PC is required.

The system kiosk runs on `tty1` without GNOME/KDE/XFCE. VMware uses Xorg/xinit; other suitable hardware can use Cage with xinit as a fallback.

### Remote browser

An operator connects from another machine. The preferred production path is:

```text
browser → HTTPS → Caddy/nginx → 127.0.0.1:8000
```

See [INSTALLATION.md](INSTALLATION.md) and [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Frontend stack

The frontend intentionally has no build framework:

```text
frontend/
├── index.html
├── app.js
├── i18n.js
└── style.css
```

It is plain HTML/CSS/JavaScript.

The application is no longer a trivial page, though. It contains the audit wizard, status polling, inventory screens, findings, report preview, network settings, login/password flows, and the separate listen/record workflow.

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
passive / active / protocol jobs
  ↓
summary
  ↓
assets / observations / assessment / findings
  ↓
report
```

The home screen also provides:

- Listen / Record;
- Network settings;
- Change password;
- previous audit history.

## Roles

Local roles are:

- `auditor`;
- `viewer`.

| Action | Auditor | Viewer |
| --- | --- | --- |
| Login and read audits/jobs/inventory/findings/reports | yes | yes |
| Change own password | yes | yes |
| Create audit | yes | no |
| Start/cancel jobs | yes | no |
| Start/stop listen capture | yes | no |
| List/download saved captures | yes | yes |
| Change network settings | yes | no |
| Suppress / accept risk / reopen a finding | yes | no |
| Generate a report | yes | no |

Role enforcement is performed by the backend, not merely by hiding buttons in JavaScript.

## Login and sessions

After authentication, the backend sets an HttpOnly session cookie.

Properties:

- random token;
- `SameSite=strict`;
- SQLite stores the token's SHA-256 digest;
- `Secure` is enabled for trusted reverse proxy or direct TLS.

If a `Secure` cookie is expected while the operator opens the site over plain HTTP, login may appear not to persist. The UI warns about that situation.

## Password change

The home screen provides **Change password**.

The user supplies:

1. current password;
2. new password;
3. confirmation.

The backend verifies the current hash, updates the password, and revokes the user's other sessions. The browser session that submitted the change remains active.

`appliance set-password` is mainly a lock-out recovery command.

## Layout

The compact baseline is a 480×320 landscape kiosk.

Key constraints:

- single column;
- minimum 44px touch targets;
- compact header;
- separate scrollable content area;
- confirmation/stop dialogs use `role="alertdialog"`.

At 900px and above, a denser laptop/desktop layout enables grids, more information per row, and a larger report preview.

The project does not maintain separate kiosk and desktop frontends.

## Job progress

The GUI polls durable job state.

If a poll fails temporarily:

- a warning is shown;
- polling retries with backoff;
- the job is not cancelled.

Stop is an explicit `auditor` action with a confirmation dialog.

The active audit ID is kept in `sessionStorage` so a reload can return to progress or summary.

This is only UI convenience. The actual source of truth is persisted backend/worker state in SQLite.

## Summary, observations, assessment, findings

These are separate views on purpose.

### Summary

A compact audit picture:

- capture interface;
- whether it had an L3 address;
- frame count;
- tagged VLAN IDs actually observed;
- LLDP/CDP neighbors;
- segment/access-vs-trunk note;
- downstream stage state.

### Observations

Normalized facts from protocol modules, such as TLS session/certificate data, SSH algorithms, or HTTP response metadata.

### Assessment

Confidence-qualified interpretation of passive evidence: VLAN hints, neighbors, STP, ARP/DHCP, and similar context.

### Findings

Rule results with severity, recommendation, evidence, and state.

A passive sensor hit does not become a finding just because it exists.

## VLAN display

The UI follows the same model as backend and reports.

An 802.1Q VLAN ID is shown as observed in traffic only when the tag actually existed in a frame.

If an access port sends untagged frames, WireScope shows untagged traffic but does not invent a VLAN ID.

An LLDP/CDP advertised native/voice VLAN is displayed as neighbor metadata and is not confused with a frame tag.

## Listen / Record

Listen / Record is a separate workflow, not the short passive capture performed as part of an audit.

The operator chooses:

- interface;
- optional BPF/tcpdump filter;
- duration;
- maximum PCAP size.

The resulting job type is:

```text
packet_capture
```

In this mode `dumpcap` runs promiscuously and the resulting PCAP is retained in the evidence store.

Default settings:

```text
duration: 120 s
max file size: 16 MiB
```

Current policy maximums:

```text
duration: 1800 s
max file size: 64 MiB
filter length: 512 chars
```

Duration `0` means capture until Stop, while the file-size limit remains a safety boundary.

### What promiscuous mode actually means

Promiscuous mode does not make a switch send all segment traffic to the host.

Without SPAN/mirroring, the NIC generally sees:

- broadcast;
- flooded traffic;
- multicast that reaches the port;
- unicast to its own MAC;
- any other traffic the switch actually forwards to that port.

`dumpcap` records everything the NIC receives, not magically every frame on the VLAN.

### BPF filter

The filter is normalized/validated separately and passed as one `dumpcap -f` argument.

No shell is used for filter execution.

## Network screen

The GUI can view and change host network configuration through backend `NetworkService` and the appliance `netctl` boundary.

If a change may remove the current management path, the backend requires additional confirmation. Frontend code cannot bypass that server-side check.

## Reports

The UI can:

- enqueue report generation (`auditor` only);
- show report history;
- open HTML preview;
- download HTML/JSON exports.

A viewer may read existing reports but cannot generate new ones.

PDF currently returns `422 pdf_not_available`.

## Error handling

The UI should not translate backend failure into “nothing found”.

Distinct cases include:

- validation error;
- worker not ready;
- missing provider;
- timeout;
- cancellation;
- partial result;
- authorization/role error;
- network-apply confirmation or failure.

## Kiosk lifecycle

The kiosk process is independent:

```text
wirescope-api      survives Chromium restart
wirescope-worker   survives Chromium restart
wirescope-kiosk    may restart independently
```

A display reload or restart therefore does not cancel an audit.

The screen is a client, not the executor.

## Browser tests

The main GUI/API workflows are fixture-based. Optional Playwright tests are marked `browser` and skipped when Playwright/Chromium is unavailable.

A headless CI system without Chromium does not fail the backend test suite just because kiosk browser tests cannot run.
