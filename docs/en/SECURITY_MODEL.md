# WireScope security model

[Русский](../SECURITY_MODEL.md) · **English**

WireScope performs network inspection itself, so its security model is built around explicit boundaries: who accepts input, which component may start external processes, where elevated privileges live, which targets are authorized, and how operator actions are recorded.

## Core rules

- API and worker run without root privileges;
- packet-capture capabilities belong only to `dumpcap`;
- active discovery requires operator-confirmed scope;
- clients cannot supply arbitrary Nmap/provider flags;
- external tools run as argv arrays without a shell;
- raw evidence is exposed by registered artifact ID, never by caller-selected filesystem path;
- mutating API operations require `auditor`;
- the normal appliance listener is `0.0.0.0:8000`;
- the operational log does not store passwords, request bodies, or session tokens;
- raw-evidence cleanup requires explicit confirmation.

## Trust boundaries

### HTTP/API

FastAPI owns authentication, role checks, and validation of interfaces, scope, addresses, ports, filters, and job parameters. User-controlled strings are not forwarded directly into a shell or scanner CLI.

### Worker

The worker executes only registered job types. Network-sensitive jobs are `passive_discovery`, `packet_capture`, `active_discovery`, and `protocol_audit`. Findings/report jobs operate only on persisted data.

### External tools

`ToolRunner` executes argument arrays and does not use `shell=True`. Providers construct the allowed argv; the HTTP API does not expose unrestricted extra flags.

## Least privilege

```text
wirescope-api            wirescope-worker
uid=wirescope            uid=wirescope
      │                        │
      └───────────┬────────────┘
                  │
                  ▼
            /usr/bin/dumpcap
        root:wireshark 0750
 cap_net_admin,cap_net_raw=eip
```

Python, Uvicorn, and the worker must not carry `CAP_NET_RAW` or `CAP_NET_ADMIN`. Elevated packet-capture rights are isolated in the narrow dumpcap boundary.

## Active discovery

An immutable confirmed-scope snapshot is persisted before Nmap starts. The worker revalidates scope and routing immediately before scanner execution.

Unspecified/multicast targets, uncontrolled IPv6 expansion, and raw user-supplied Nmap flags are rejected. WireScope does not elevate Nmap. NSE/`-sC`, vuln, brute-force, exploit, and DoS scripts are not part of the default discovery path.

## Protocol audits and capabilities

A protocol module runs only for a matching inventory service inside authorized scope. Default modules do not guess credentials or community strings.

A missing binary is represented as an unavailable capability / `tool_unavailable`, not as a passed check.

```text
GET /api/v1/capabilities
```

Core readiness and optional-provider availability are separate concepts.

## Authentication and roles

| Action | Auditor | Viewer |
| --- | --- | --- |
| Read audits/inventory/findings/reports | yes | yes |
| Dashboard/diff/evidence | yes | yes |
| Change own password | yes | yes |
| Create audit / start job | yes | no |
| Cancel/retry terminal job | yes | no |
| Change network configuration | yes | no |
| Change finding state | yes | no |
| Diagnostics/audit log/maintenance | yes | no |

Session tokens are random. The browser receives an HttpOnly cookie while SQLite stores only its SHA-256 digest. `SameSite=strict` is used; `Secure` is enabled for direct TLS/trusted-proxy deployments. Password hashes use PBKDF2-HMAC-SHA256.

## Operational audit log

Significant mutating requests and login attempts are stored in `operational_events`.

Each event records:

- UTC timestamp;
- actor/role;
- stable action name;
- normalized API path;
- HTTP status;
- client IP;
- audit id when it can be derived from the path.

**Never stored:** request body, password, session cookie/token, provider stdout/stderr.

The operational log is different from job events: job events describe execution history, while the operational log records actions taken against the appliance.

The log is auditor-only:

```text
GET /api/v1/audit-log
```

A failure to write an operational event does not turn an otherwise successful operator request into an outage. Database/migration health is visible separately through diagnostics.

## Web listener, firewall, and TLS

WireScope is a network appliance whose UI should be reachable through any configured Ethernet/Wi-Fi interface. Application settings, argparse, installer, and upgrade paths therefore default to:

```text
0.0.0.0:8000
```

This means listening on local IPv4 interfaces; it does not itself imply Internet exposure. Actual reachability depends on addressing, routing, VLANs, and firewall policy.

The local kiosk opens `127.0.0.1:8000`. Loopback-only deployment remains an explicit `--bind-host 127.0.0.1` option. Direct TLS, reverse proxy, and firewall restrictions remain deployment controls.

## Evidence

PCAP and raw provider output may contain sensitive data. Clients do not choose paths; WireScope registers UUID artifacts in SQLite.

Evidence writes follow temporary file → flush/fsync → atomic rename → SHA-256 → metadata registration.

Normal permissions:

```text
directories: 0700
files:       0600
```

Artifact access is audit-scoped:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

The backend verifies that the artifact belongs to the requested audit.

## Retention and cleanup

Normalized inventory, findings, and reports are not automatically deleted. Aged temporary/debug/raw evidence becomes cleanup candidates.

Raw cleanup is explicitly two-step:

```text
preview: confirm=false
apply:   confirm=true
```

PCAP, Nmap XML, and protocol raw output are removed only after explicit auditor confirmation. Cleanup removes both the file and the artifact metadata row, preventing silent evidence loss.

## SQLite and durability

SQLite stores audits, jobs/events, confirmed scopes, inventory, findings, reports, users/sessions, operational events, and artifact references.

Runtime policy uses WAL, foreign keys, a busy timeout, short transactions, and `synchronous=FULL` by default. Do not place the live database on NFS.

## Resource locking, cancellation, and retry

Locks live in SQLite. Cancellation is persistent: the worker terminates the subprocess group and moves the job to `cancelled`.

After worker restart:

- queued jobs remain queued;
- running jobs become interrupted;
- stale locks are released.

There is no uncontrolled automatic network retry. An auditor may explicitly retry a `failed`, `interrupted`, or `cancelled` stage. Retry creates a new job and preserves the terminal source job unchanged.

## Network configuration helper

Network changes pass through the separate `netctl` privilege boundary. The API itself does not become root and does not execute arbitrary sudo commands. A potentially disruptive management-path change requires server-side confirmation.

## Diagnostics

Auditor-only diagnostics provides a safe operational snapshot:

```text
GET /api/v1/diagnostics
GET /api/v1/diagnostics/export
```

It contains platform/version, listener state, capabilities, SQLite quick-check, migration/worker state, disk/evidence usage, retention, and recent operational events. Secrets and raw provider contents are excluded from the export.

## Backup and restore

A backup contains SQLite and optionally evidence, so it requires the same protection as the live data directory. SQLite snapshots use the backup API. Restore checks `PRAGMA integrity_check` before replacing the working database.

## API docs and errors

Swagger/OpenAPI/ReDoc can be disabled with `WIRESCOPE_DOCS_ENABLED=false`. `/health` and `/ready` remain public.

HTTP clients receive typed safe errors rather than Python tracebacks.

## Operational checklist

- API/worker are not root;
- Python carries no network capabilities;
- `dumpcap` is not setuid and has the expected capabilities;
- `/etc/wirescope` and `/var/lib/wirescope` are not world-readable;
- the generated initial-admin secret is protected and temporary material removed;
- listener/firewall/TLS policy matches the deployment segment;
- scope caps are not raised without a reason;
- diagnostics reports SQLite `ok`, worker ready, and sufficient disk space;
- backups receive the same protection as database/evidence.

The formal release checklist is in [RELEASE_READINESS.md](RELEASE_READINESS.md).
