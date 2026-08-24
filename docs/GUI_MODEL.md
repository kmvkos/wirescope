# WireScope operator GUI

Milestone 7 adds the local operator interface. Auditors complete an audit
from the browser; they do not use a shell. Viewers can inspect results but
cannot start or cancel work. The GUI is a client of the durable API and
never owns job lifetime. Production deployment is a generic Linux appliance.
Operators use a **local display kiosk** (loopback, no management network) or a
LAN browser. A 480×320 layout is the compact kiosk baseline. Raspberry Pi
hardware is optional; Raspberry Pi OS is not required.

```text
login
  → home (audits · Прослушивание · Сеть · Сменить пароль)
  → new audit
  → environment
  → interface
  → network / VLAN / scope
  → profile
  → confirmation
  → progress
  → summary
  → assets / observations / assessment / findings
  → report

listen
  → interface + optional tcpdump filter + duration/size
  → progress (frames / bytes / elapsed)
  → download pcap
```

The frontend remains vanilla HTML, CSS, and JavaScript. A framework is still
unnecessary: the workflow is a linear wizard plus read-only result screens.

## Listen / record

**Прослушивание** is not the 30-second audit capture. An auditor picks any
selectable NIC (same rule as audits, including the GUI interface), an optional
tcpdump/BPF filter, a duration and/or max pcap size, then starts a
`packet_capture` job. Dumpcap runs in promiscuous mode and writes a pcap into
the evidence store (never a SQLite BLOB). Cancel stops the dumpcap process
group; frames already written are kept.

Without SPAN/mirroring on the switch the NIC only sees broadcasts, flooded
frames, and unicast to its own MAC. Promiscuous mode still records
**everything the NIC actually receives** — not all traffic on the segment.

Viewers may list and download sessions. They cannot start or stop them.
Default Pi-safe limits are 120 s and 16 MiB (overridable; max 30 min / 64 MiB).

## Layout

The default layout targets a 480×320 landscape kiosk (local operator
console). Сеть до вашего ПК не нужна: откройте GUI на этом компьютере / киоск.

- single column;
- 44px minimum touch targets;
- compact header with health and session chip;
- scrollable main pane;
- confirmation and stop dialogs use `role="alertdialog"`.

A laptop/desktop stylesheet (`min-width: 900px`) adds denser grids and a
taller report preview without changing the kiosk flow.

## Roles

Local users persist in SQLite. Roles are `auditor` and `viewer`.

| Action | Auditor | Viewer |
| --- | --- | --- |
| Sign in / view audits, jobs, inventory, findings, reports, listen sessions | yes | yes |
| Change own password | yes | yes |
| Create audits, enqueue jobs, start/stop listen capture, cancel, change finding state, generate reports, edit network | yes | no |

Sessions are HttpOnly `SameSite=strict` cookies. The cookie stores a random
token; SQLite stores only the SHA-256 digest. Login uses PBKDF2-HMAC-SHA256.
LAN installs that terminate TLS (`--trust-proxy` or direct TLS) set the
`Secure` flag; the Russian GUI warns if that cookie is used over HTTP.

Bootstrap users are created only when the `users` table is empty and
`WIRESCOPE_BOOTSTRAP_AUDITOR_*` / `WIRESCOPE_BOOTSTRAP_VIEWER_*` are set.
There is no built-in default password. The appliance installer creates the
first auditor from a mode `0600` password file; see
[INSTALLATION.md](INSTALLATION.md).

After sign-in, **Сменить пароль** on the home screen (same style as **Сеть**)
lets the current user set a new password: current, new, confirm. The API
verifies the current hash, writes the new hash, and revokes other sessions
for that user. The browser session that submitted the form stays signed in.
Wrong current password returns a generic `401`. The CLI `set-password`
command remains for lock-out recovery only.

## Progress and recovery

The UI polls job status with backoff. A failed poll shows a warning and
retries; it does not cancel the job. Stop is an explicit auditor action with
a confirmation dialog.

Active audit identity is kept in `sessionStorage` so a display refresh can
resume the progress or summary screen. Reloading Chromium, restarting the
kiosk process, or closing the tab does not call cancel. The API and worker
keep running independently.

## Observations, assessments, and findings

The GUI keeps those layers on separate screens:

- **Summary** — audit status plus the passive picture: capture NIC L3 yes/no,
  frame count, tagged VLAN IDs actually seen, CDP/LLDP neighbors, and the
  access-vs-trunk VLAN note;
- **Observations** — protocol-module facts from `/api/audits/{id}/observations`;
- **Assessment** — confidence-qualified interpretations from a completed
  passive job result, including VLANs, neighbors, STP, and ARP;
- **Findings** — severity-bearing rule results from `/api/audits/{id}/findings`.

Passive sensor hits stay inside the passive result document. They are not
shown as findings. VLAN IDs are never invented for untagged access-port
traffic.

## Reports

HTML and JSON export use the Milestone 6 endpoints. PDF remains
`422 pdf_not_available`. Generate is auditor-only; viewers can open an
existing report.
