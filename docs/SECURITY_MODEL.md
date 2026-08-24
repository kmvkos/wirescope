# WireScope security model

## Trust boundaries

- FastAPI validates external requests and creates durable metadata.
- `JobService` owns state transitions and transaction boundaries.
- The worker executes only registered internal job types.
- `ToolRunner` executes argument arrays without a shell.
- `dumpcap` is the only component with packet-capture capabilities.
- Nmap runs unprivileged by default and only after authorized-scope and route
  validation. Raw-socket features are used only when the process already has
  `CAP_NET_RAW`; the backend is not granted extra privileges for scanning.
- Protocol-audit tools run unprivileged against confirmed inventory addresses
  that still lie inside authorized scope. Command builders emit argument
  arrays only; user-supplied tool flags are rejected.
- SQLite and evidence roots are writable only by the WireScope service user.

Authentication is local SQLite users with roles `auditor` and `viewer`.
Sessions use HttpOnly cookies; mutating routes require `auditor`. Health and
readiness stay public so a kiosk can show appliance state before login. Bind
the API to loopback or another trusted local boundary until Milestone 8 adds
remote transport controls. Do not expose the API to an untrusted network.

## Job safety

Terminal jobs cannot transition back to running. There are no automatic
retries. Running cancellation is persistent and propagated to subprocess
groups through a cooperative token.

Only one healthy worker supervisor may run. Database-backed resource locks
prevent simultaneous passive captures on one interface, serialize active
discovery against that same interface, enforce global capture/Nmap limits,
serialize protocol audits per audit (`audit:<id>` plus the `protocol_audit`
group), serialize findings evaluation per audit (`audit:<id>` plus the
`findings` group), and serialize report generation per audit (`audit:<id>`
plus the `report` group). Findings evaluation and report generation do not
take `interface:<name>` and do not invoke scanners.

API errors contain typed safe fields. Python tracebacks remain in structured
debug logs and are not returned as HTTP responses.

## Evidence

Clients never choose evidence paths. Internal UUIDs generate relative paths
below the configured evidence root. Files are mode `0600`; directories are
mode `0700`.

Finished artifacts are flushed, atomically renamed, hashed with SHA-256, then
registered in SQLite. Result JSON includes a schema name and version.

Raw PCAP can contain credentials, identifiers, and private traffic. Retention
is disabled by default. Enabling retention is an operator policy decision and
requires protected storage and eventual deletion/export procedures.

## Database

SQLite foreign keys are enabled on every application connection. WAL and short
transactions permit one API and one controlled worker process without holding
locks during scans.

The database contains user-selected scope, target/interface values, event
history, structured errors, references to evidence, local operator accounts,
and hashed session tokens. File permissions and backup handling must protect
it as audit data.

## Recovery

After worker restart, previously running jobs become `interrupted` with
`application_restart`; they are not resumed automatically. Queued jobs remain
eligible. Resource locks and stale worker records are cleared transactionally.

Startup cleanup only removes controlled temporary/orphan files. It never
deletes registered audit evidence without explicit retention policy.
