# WireScope security model

[Русский](../SECURITY_MODEL.md) · **English**

WireScope actively inspects networks, so its security model is built around concrete boundaries: who accepts input, who may start processes, which component owns packet-capture privileges, and which targets are actually authorized.

## The short version

- API and worker do not run as root.
- Packet-capture capabilities belong only to `dumpcap`.
- Active discovery requires a confirmed scope.
- Clients cannot supply arbitrary Nmap or provider flags.
- External tools run as argv arrays without a shell.
- Raw evidence is stored behind internal artifact IDs, not caller-supplied paths.
- Mutating operational APIs require the `auditor` role.
- Plain HTTP exposed to a LAN is not the recommended production setup.

## Trust boundaries

### HTTP/API boundary

FastAPI accepts external input and is responsible for:

- authentication;
- role checks;
- validation of interfaces, scope, addresses, ports, filters, and job parameters;
- durable audit/job metadata;
- controlled read access through API models.

A user-controlled string is not forwarded directly into a shell or scanner command line.

### Job boundary

The worker executes only registered internal job types.

Network-sensitive jobs currently include:

- `passive_discovery`;
- `packet_capture`;
- `active_discovery`;
- `protocol_audit`.

`findings_evaluation` and `report_generation` operate only on persisted data and do not contact the network themselves.

### External-tool boundary

`ToolRunner` executes argument arrays. `shell=True` is not used on this path.

Provider modules construct the allowed argv. The API does not expose an unrestricted “extra flags” field for Nmap or other tools.

## Least privilege

A normal system install should look like this:

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

Useful checks:

```bash
getcap /usr/bin/dumpcap
stat -c '%U:%G %a' /usr/bin/dumpcap
sudo -u wirescope /usr/bin/dumpcap -D
getcap /opt/wirescope/.venv/bin/python || true
```

The Python interpreter should return without capabilities.

`appliance verify` also checks that `dumpcap` is not setuid, permissions have the expected shape, and the backend did not inherit packet-capture capabilities.

### Why `dumpcap` gets privileges instead of the backend

WireScope does not run the whole application as root just to capture packets. `dumpcap` is a narrow capture provider with the minimum file capabilities required for that task.

That keeps a bug in the API, parser, or frontend from automatically turning into a root-level process and packet-access bug.

## Nmap and active discovery

Nmap starts only after server-side scope confirmation and route validation.

An immutable confirmed-scope snapshot is persisted before the job runs. The worker validates that snapshot again before invoking Nmap.

The following are rejected:

- `0.0.0.0/0`;
- `::/0`;
- multicast ranges;
- uncontrolled expansion of large IPv6 prefixes;
- raw user-supplied Nmap flags.

WireScope does not elevate Nmap. If raw-socket privileges already exist, the provider may use the corresponding discovery/scanning methods. Otherwise it falls back to TCP connect and records skipped UDP/OS-detection capabilities.

Active discovery does not use NSE, `-sC`, `vuln`, brute-force, exploit, or DoS scripts.

See [SCANNING_MODEL.md](SCANNING_MODEL.md).

## Protocol audits

A protocol module runs only when:

1. a matching service already exists in inventory;
2. the module predicate matches;
3. the chosen asset address is still inside authorized scope;
4. the module safety class is allowed by the current profile.

Current default modules do not guess credentials or community strings.

Examples:

- SMB uses a conservative null-session probe;
- SNMP uses an SNMPv3 noAuth probe without `public/private` guessing or walks;
- LDAP uses anonymous base DSE;
- HTTP does not follow redirects automatically;
- `testssl.sh`, Nikto, and Nuclei are `never-default` stubs.

A missing binary produces `tool_unavailable`; it is not evidence that the protocol is absent.

## Authentication and roles

Users are local SQLite records.

| Action | `auditor` | `viewer` |
| --- | --- | --- |
| Read audits/jobs/inventory/findings/reports | yes | yes |
| Change own password | yes | yes |
| Create audits | yes | no |
| Start/cancel jobs | yes | no |
| Listen/record capture | yes | list/download only |
| Change network configuration | yes | no |
| Change finding state | yes | no |
| Generate reports | yes | no |

Session tokens are random.

- the browser receives an HttpOnly cookie;
- cookies use `SameSite=strict`;
- SQLite stores only the token's SHA-256 digest;
- cookies become `Secure` when direct TLS or a trusted reverse proxy is configured.

Passwords use PBKDF2-HMAC-SHA256.

There is no built-in default password.

## Bind address and TLS

The application-level default is `127.0.0.1:8000`. The installer CLI currently has a separate `0.0.0.0` default, so production commands set the intended bind explicitly.

### Local kiosk

For an autonomous appliance:

```text
127.0.0.1:8000
```

The API does not need to be reachable from another host at all.

### LAN access

Recommended layout:

```text
management browser
      │ HTTPS :443
      ▼
Caddy / nginx
      │ loopback HTTP
      ▼
127.0.0.1:8000
```

Installer example:

```bash
sudo ./packaging/install.sh \
  --bind-host 127.0.0.1 \
  --trust-proxy \
  --generate-admin-password
```

In this mode:

- API remains on loopback;
- session cookies are `Secure`;
- forwarded headers are trusted only from the loopback proxy;
- TCP 8000 does not need to be exposed to the LAN.

Example proxy/firewall snippets live under `packaging/proxy/`.

### Direct TLS

Direct Uvicorn TLS is also supported, commonly on port 8443. Certificate/key paths belong in `wirescope.env`; PEM contents must not be embedded in systemd units.

### Plain HTTP on `0.0.0.0`

Technically supported, but not the recommended LAN configuration. If used, the port should be restricted to the management network by the host firewall.

The installer does not rewrite firewall policy automatically.

## API documentation

Swagger/OpenAPI/ReDoc may be enabled in development.

Production appliance configuration should set:

```text
WIRESCOPE_DOCS_ENABLED=false
```

`/api/health` and `/api/ready` remain public so a kiosk or reverse proxy can check appliance state before login.

## Evidence and sensitive data

A PCAP may contain:

- clear-text credentials;
- internal addresses and hostnames;
- cookies/tokens;
- user traffic;
- device identifiers.

The evidence root must therefore be treated as sensitive audit storage.

Clients do not choose evidence paths. WireScope generates internal UUID-based locations.

Artifact write path:

1. temporary file;
2. flush/fsync;
3. atomic rename;
4. SHA-256;
5. metadata registration in SQLite.

Normal modes are:

```text
directories: 0700
files:       0600
```

Raw PCAP retention for the normal passive-audit path is disabled by default (`passive_retain_capture=false`). In Listen / Record mode the PCAP is the intended output and is retained as evidence.

Retention is an operator-policy concern. Policy-driven automatic deletion of registered audit evidence is not implemented yet.

## SQLite

SQLite contains:

- selected scope and interfaces;
- jobs/events/errors;
- inventory;
- findings;
- report metadata;
- local users;
- hashed sessions;
- evidence references.

It should be protected as audit data.

Do not place the live database on NFS.

Runtime database settings include:

- WAL;
- foreign keys;
- busy timeout;
- short transactions;
- `synchronous=FULL` by default.

Operator backup/restore:

```bash
python -m appliance backup
python -m appliance restore <archive>
```

## Resource locking and concurrency

Resource locks live in SQLite.

They prevent conflicts even across worker threads:

- `interface:<name>` prevents simultaneous capture and active discovery on one interface;
- packet capture has a global resource-group limit;
- active discovery has its own group limit;
- protocol audits serialize by audit/group;
- findings and reports serialize separately and do not hold an interface lock.

Default concurrency is conservative: the main network jobs run one at a time.

Only one healthy worker supervisor should own the supervisor lease, preventing an accidentally launched second process from multiplying configured concurrency.

## Cancellation

Cancellation of a running job is persistent state, not just an in-memory flag.

The worker observes the request, sets the cancellation token, and `ToolRunner` terminates the subprocess group.

A cancelled job ends as `cancelled`, not `failed`.

Valid partial observations already persisted before cancellation may remain in inventory/evidence.

## Restart recovery

After a worker restart:

- queued jobs remain queued;
- old running jobs become `interrupted`;
- the error code is `application_restart`;
- resource locks are released;
- jobs are not resumed or retried automatically.

This is intentional: an arbitrary network scan is safer to restart explicitly than to resume from an uncertain execution point.

Restarting the browser or kiosk does not affect job lifetime.

## Network configuration helper

WireScope can change host network configuration through a separate `netctl` privilege boundary. The API itself does not become root and does not execute arbitrary `sudo` commands.

System installs use a tightly scoped helper/sudoers path. Input still passes model validation and confirmation checks, especially when a change may remove the current management path.

## Logging

HTTP clients receive typed safe errors. Python tracebacks are not returned in API responses.

The worker emits structured operational logs with audit/job context. A separate immutable security audit-log table does not exist yet; this is current technical debt.

## Production checklist

At minimum, verify:

- API/worker are not root;
- Python has no network capabilities;
- `dumpcap` is not setuid and has the expected file capabilities;
- `WIRESCOPE_DOCS_ENABLED=false`;
- LAN UI is HTTPS unless the host is an explicitly isolated lab system;
- TCP 8000 is not exposed when using a reverse proxy;
- `/etc/wirescope` and `/var/lib/wirescope` are not world-readable;
- `initial-admin.txt` has been removed after the password was stored safely;
- backups receive the same protection as the main database/evidence;
- scope caps have not been raised without a documented reason.
