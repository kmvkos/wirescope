# WireScope security model

[Русский](../SECURITY_MODEL.md) · **English**

WireScope actively inspects networks, so its security model is based on explicit boundaries: who accepts input, which component may start external processes, where elevated privileges live, and which targets are authorized.

## Core rules

- API and worker run without root privileges.
- Packet-capture capabilities belong only to `dumpcap`.
- Active discovery requires operator-confirmed scope.
- Clients cannot supply arbitrary Nmap/provider flags.
- External tools run as argv arrays without a shell.
- Raw evidence is exposed through registered artifact IDs, not caller-selected filesystem paths.
- Mutating APIs require the `auditor` role.
- A normal appliance listens on `0.0.0.0:8000` so the UI is reachable through any configured physical or Wi‑Fi interface.

## Trust boundaries

### HTTP/API

FastAPI owns authentication, role checks, and validation of interfaces, scope, addresses, ports, filters, and job parameters. User-controlled strings are not forwarded directly into a shell or scanner CLI.

### Worker

The worker executes only registered job types. Network-sensitive jobs are:

- `passive_discovery`;
- `packet_capture`;
- `active_discovery`;
- `protocol_audit`.

`findings_evaluation` and `report_generation` operate only on persisted data.

### External tools

`ToolRunner` executes argument arrays and does not use `shell=True`. Providers build the allowed argv; the HTTP API does not expose unrestricted extra flags.

## Least privilege

A normal system install looks like this:

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

Python, Uvicorn, and the worker must not carry `CAP_NET_RAW` or `CAP_NET_ADMIN`.

```bash
getcap /usr/bin/dumpcap
stat -c '%U:%G %a' /usr/bin/dumpcap
sudo -u wirescope /usr/bin/dumpcap -D
getcap /opt/wirescope/.venv/bin/python || true
```

Elevated packet-capture rights are isolated in the narrow capture provider instead of running the entire backend as root.

## Active discovery

An immutable confirmed-scope snapshot is persisted before Nmap starts. The worker revalidates scope and routing immediately before invoking the scanner.

Rejected inputs include:

- `0.0.0.0/0`;
- `::/0`;
- multicast ranges;
- uncontrolled expansion of large IPv6 prefixes;
- raw user-supplied Nmap flags.

WireScope does not elevate Nmap. Without raw sockets, the provider uses supported fallbacks and records unavailable capabilities. NSE, `-sC`, `vuln`, brute-force, exploit, and DoS scripts are not part of the default discovery path.

See [SCANNING_MODEL.md](SCANNING_MODEL.md).

## Protocol audits and capabilities

A protocol module runs only for a matching inventory service whose address remains inside authorized scope.

Default modules do not guess credentials or community strings. A missing optional binary is represented as an unavailable capability / `tool_unavailable`, never as a passed check.

`GET /api/v1/capabilities` exposes the tools actually available on the appliance. Readiness depends on the core capture/decode dependencies; a missing optional provider such as `ssh-audit` or `smbclient` does not make the whole appliance unready.

## Authentication and roles

Local roles are `auditor` and `viewer`.

| Action | `auditor` | `viewer` |
| --- | --- | --- |
| Read audits/jobs/inventory/findings/reports | yes | yes |
| Dashboard / diff / capabilities / evidence | yes | yes |
| Change own password | yes | yes |
| Create audits | yes | no |
| Start/cancel jobs | yes | no |
| Listen/Record | yes | no |
| Change network configuration | yes | no |
| Change finding state | yes | no |
| Generate reports | yes | no |

Session tokens are random. The browser receives an HttpOnly cookie while SQLite stores only its SHA-256 digest. `SameSite=strict` is used; `Secure` is enabled for direct TLS or trusted-proxy deployments. Passwords use PBKDF2-HMAC-SHA256. There is no permanent built-in default password.

## Web listener, firewall, and TLS

### Default appliance policy

WireScope is intended to behave as a standalone network appliance that an operator reaches through whichever interface is available in the current segment. Application settings, installer, and upgrade path therefore default to:

```text
0.0.0.0:8000
```

This means “listen on all local IPv4 interfaces”; it does not by itself make the service Internet-reachable. Actual reachability still depends on addressing, routing, VLANs, and host/network firewall policy.

The local kiosk continues to open:

```text
http://127.0.0.1:8000/
```

because loopback is simply another local path to the same listener.

### Restricted deployments

A particular deployment can opt into loopback-only binding:

```bash
sudo ./packaging/install.sh --bind-host 127.0.0.1
```

TCP/8000 may also be restricted with a firewall, protected with direct TLS, or placed behind a reverse proxy. The installer does not rewrite firewall policy automatically.

Direct TLS example:

```bash
sudo ./packaging/install.sh \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

`GET /api/v1/capabilities` reports the effective bind host/port, TLS state, and trust-proxy state.

## Evidence

PCAP and raw provider output may contain sensitive data. Clients do not select artifact paths; WireScope creates UUID-based artifacts and registers their metadata in SQLite.

Evidence writes follow temporary file → flush/fsync → atomic rename → SHA-256 → metadata registration.

Normal permissions are:

```text
directories: 0700
files:       0600
```

Artifact downloads are audit-scoped:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

The backend verifies that the artifact belongs to the requested audit. Normal passive captures are not retained long-term by default (`passive_retain_capture=false`); Listen/Record intentionally retains its PCAP as evidence.

## SQLite and durability

SQLite stores audits, jobs/events, confirmed scopes, inventory, findings, report metadata, local users/sessions, and evidence references.

Runtime policy includes:

- WAL;
- foreign keys;
- busy timeout;
- short transactions;
- `synchronous=FULL` by default.

Do not place the live database on NFS.

## Resource locking, cancellation, and restart

Locks live in SQLite. `interface:<name>` prevents conflicting capture/active work from using the same interface concurrently, while resource groups limit overall concurrency.

Cancellation is persistent state. The worker terminates the subprocess group and moves the job to `cancelled`.

After worker restart:

- queued jobs stay queued;
- old running jobs become `interrupted` with `application_restart`;
- locks are released;
- network scanner jobs are not automatically resumed or retried.

Restarting Chromium or the kiosk does not affect durable jobs.

## Network configuration helper

Host network changes pass through a separate `netctl` privilege boundary. The API itself does not become root and does not execute arbitrary `sudo` commands. A change that may break the management path requires server-side confirmation.

## API docs and logging

Swagger/OpenAPI/ReDoc can be disabled with:

```text
WIRESCOPE_DOCS_ENABLED=false
```

`/api/health` and `/api/ready` remain public for appliance health checks.

HTTP clients receive typed safe errors without Python tracebacks. The worker emits structured operational logs. A dedicated immutable security audit-log table is still future work.

## Operational checklist

- API/worker are not root.
- Python has no network capabilities.
- `dumpcap` is not setuid and has the expected capabilities.
- `/etc/wirescope` and `/var/lib/wirescope` are not world-readable.
- the generated initial-admin secret is stored and the temporary file removed;
- firewall/TLS policy matches the deployment segment;
- scope caps are not raised without a reason;
- backups receive the same protection as the live database/evidence.
