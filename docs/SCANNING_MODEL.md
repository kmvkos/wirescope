# WireScope scanning model

Milestone 3 adds **controlled active discovery**. It produces an asset and
service inventory. It does not create vulnerability findings.

## Observed hint versus authorized scope

Passive discovery and environment inspection may suggest networks, gateways,
or host addresses. Those values are **observed network hints**. They must not
start Nmap by themselves.

An **authorized audit scope** is a server-validated snapshot bound to an
`audit_id`. Active discovery starts only after that snapshot is confirmed:

```text
Environment Discovery
        ↓
Passive Discovery
        ↓
Scope Confirmation
        ↓
Active Host Discovery
        ↓
Asset Inventory
        ↓
TCP / selected UDP Discovery
        ↓
Service Fingerprinting
        ↓
OS / Device Hints
        ↓
Passive + Active Correlation
        ↓
Persistent Asset / Service Inventory
```

The API request carries targets and a profile, never raw Nmap flags. The
worker re-validates the same snapshot before invoking the scanner.

## Scope model

`engine/scope.py` uses Python `ipaddress` and accepts:

- a single IPv4 or IPv6 address;
- an IPv4 or IPv6 CIDR;
- multiple mixed targets, with duplicates and covered prefixes removed.

Unspecified and multicast networks are rejected (`0.0.0.0/0`, `::/0`,
`224.0.0.0/4`, and equivalent IPv6). Scope size is counted **before** a job is
created. Frontend checks are not trusted.

Confirmed scope rows are immutable: profile, interface, canonical targets,
address families, address count, route context, timing policy, actor, and a
snapshot hash. `activated_at` is set when active discovery actually starts.

## Safety limits

Defaults are sized for a Raspberry Pi 4 / 4 GB appliance and a typical LAN
audit, not an unattended enterprise sweep:

| Profile    | Default IPv4 cap | Rough CIDR equivalent |
| ---------- | ---------------- | --------------------- |
| Discovery  | 4,096 addresses  | `/20`                 |
| Standard   | 1,024 addresses  | `/22`                 |
| Deep       | 256 addresses    | `/24`                 |

IPv6 is independently capped at 256 addresses so a `/64` cannot be expanded.
Limits are host-count based rather than prefix-length based so mixed target
lists stay honest.

Set `WIRESCOPE_ALLOW_LARGE_SCOPES=true` plus higher `WIRESCOPE_*_MAX_TARGETS`
values when an administrator deliberately authorizes a larger enterprise
scope. The unspecified-network prohibition remains in force.

## Routing and interface validation

`engine/routes.py` resolves each canonical target with `ip -j -{4,6} route
get` through `ToolRunner`. Before Nmap sees an interface name the backend
checks that:

- the interface exists and passes capture/interface policy;
- the link is UP;
- the selected interface is the route `dev`;
- a source address exists and matches the target family;
- VLAN subinterfaces are accepted only when they already exist (`eth0.10`).
  WireScope does not create VLAN interfaces in Milestone 3.

Without an L3 address on the capture NIC, Deep (and any other active profile)
stays blocked unless a VLAN subinterface already has an address or the
operator confirms extra on-link CIDRs. `0.0.0.0/0` and `::/0` are never
accepted. Passive capture still runs; it does not invent a VLAN ID for
untagged access-port traffic.

The resolved context records target, source address, gateway, directly
connected versus routed, address family, and link state. Unknown interface
names are never forwarded to Nmap.

## Scanner profiles

Timing is part of the profile. The default is **T3**. T5 is never used.

### Discovery

Fast live-host inventory. Privileged directly-connected IPv4 uses ARP (`-PR`).
Routed IPv4 uses ICMP echo/timestamp plus TCP probes to 22/80/443. IPv6 uses
neighbor discovery when privileged, otherwise TCP probes. TCP/UDP service
scans and OS detection are off.

### Standard

Default WireScope inventory profile, intended to finish a `/24` in a
reasonable LAN window:

- host discovery as above;
- TCP `--top-ports 1000`;
- service detection `-sV --version-intensity 5`;
- OS detection when `CAP_NET_RAW` is available;
- curated UDP: 53, 67, 68, 69, 111, 123, 137, 161, 162, 500, 623, 1900, 4500,
  5353, 5355.

### Deep

Same host-discovery policy, then TCP `1-65535`, version intensity 7, OS
detection when privileged, and an expanded UDP set. Deep still does **not**
enable NSE, `-sC`, `vuln`, brute, auth, exploit, or DoS scripts.

## Nmap provider

`providers/nmap.py` is the only Nmap execution path. It:

- locates the binary and parses `nmap --version`;
- detects `CAP_NET_RAW` / euid 0 without raising backend privileges;
- builds argv arrays (`shell=True` is forbidden);
- writes validated targets to a `0600` file under `nmap_runtime_dir` (`-iL`);
- requests XML (`-oX`) and stores it as an evidence artifact, not a SQLite
  BLOB;
- honors ToolRunner timeouts and process-group cancellation.

Privilege fallback:

```text
SYN / ARP / OS / UDP unavailable
        ↓
TCP connect (`-sT`)
UDP and OS detection skipped and recorded
```

The actual methods, ports, timing, and fallbacks are stored in the compact
active-discovery result. User-facing job status does not include the full CLI
or the XML.

One audit pipeline runs a small number of Nmap processes (host discovery, TCP,
optional UDP) against a target list. It does not spawn one process per host.
`WIRESCOPE_MAX_ACTIVE_DISCOVERY_JOBS` defaults to 1.

## Host state

Missing ICMP echo is not “host down”. Inventory states are:

- `observed` — passive evidence only;
- `responsive` — Nmap reported `up`;
- `unresponsive` — a singleton target produced no response;
- `unknown` — Nmap reported an indeterminate host state.

Bulk CIDR “down” hosts are not materialized as assets. Tool failure is a job
error, never “0 hosts found”.

## Inventory and correlation

Assets are not keyed globally by IP. An asset has optional MAC/vendor, OS
hint, device-class hint, and timestamps. `asset_addresses` and `asset_names`
carry provenance. `services` are unique per `(asset, protocol, port)`.

Deterministic correlation uses exact MAC then exact IP. If MAC identity and IP
identity disagree, WireScope records an observation and does **not** merge the
assets. Hostnames from PTR, DHCP, mDNS, LLMNR, NBNS, and Nmap accumulate;
later sources do not erase earlier ones.

MAC vendor lookup is local (`/usr/share/ieee-data/oui.txt` or the bundled
subset). There is no per-MAC HTTP query. Missing vendor is not an error.

OS matches are hints with accuracy and confidence. They are never
`confirmed`. Device-class hints (`server-like`, `workstation-like`,
`network-device-like`, `printer-like`, `iot-like`, `unknown`) are the same:
heuristic, evidenced, and not findings.

## Resource locking

Active discovery takes the exclusive `interface:<name>` lock (the same key as
packet capture) and the `active_discovery` group with
`max_active_discovery_jobs`. Capture and Nmap therefore cannot share an
interface, and the Pi will not run overlapping active scans by default.

## Network impact

Standard `/24` at T3 is the intended LAN default. Deep full-TCP is slower and
noisier; keep the address cap at `/24` unless an administrator raises it.
IPv6 scans never brute-force a `/64`. Cancellation kills the Nmap process
group and marks the job `cancelled`, not `failed`. Partial inventory from
completed stages is kept.

## Protocol audits

Milestone 4 adds **gated, service-aware protocol audits**. They enrich the
inventory with normalized protocol observations. They are **not** a findings
engine. Weak SSH algorithms, expired certificates, missing HTTP headers, and
similar facts stay observations until Milestone 5 rules interpret them.

```text
Asset / Service inventory (M3)
        ↓
Service predicate match
        ↓
Enqueue protocol_audit job
        ↓
Provider command builder (argv arrays, ToolRunner)
        ↓
Parse fixture/tool output
        ↓
Normalized observations + evidence artifacts
        ↓
Persist against asset/service
        ↓
Compact job summary + listing API
```

### Plugin contract

Each module in `protocol_audits/modules/` declares:

- predicates on port, transport, service name, product, and tunnel;
- required tool and optional minimum version;
- safety class: `safe` (default profile), `gated`, or `never-default`;
- argv-only command builder;
- parser that does not touch SQLite;
- timeout budget (default 20 seconds, never Nmap `-T5`).

Adding a module is a registry registration. The orchestrator is not edited.

### Dispatch

The job loads open inventory services, confirmed-scope addresses, and the
module registry. A module runs only when a predicate matches **and** the
asset address is inside the authorized scope. FTP-only hosts produce no SSH
work. Missing tools produce `tool_unavailable` observations and do not fail
the job or claim that the protocol is absent.

### Default modules

| Module | Predicates (summary) | Tool | What is recorded |
| ------ | -------------------- | ---- | ---------------- |
| SSH | TCP/22, `ssh`, OpenSSH/Dropbear | `ssh-audit` | banner, KEX/host-key/cipher/MAC lists |
| TLS | 443/636/993/995/465/8443, `https`/`ldaps`, `tunnel=ssl` | `openssl s_client` | protocol, cipher, cert subject/issuer/dates, verify code |
| HTTP | 80/8080/443/…, `http`/`https` | `curl` | status, selected headers, HTML title |
| DNS | TCP/UDP 53, `domain` | `dig` CHAOS `version.bind` / `id.server` | identity strings, RA/RD/AA flags |
| SMB | 139/445, `microsoft-ds` | `smbclient -N -L` | null-session accepted or NT_STATUS refusal |
| SNMP | UDP/161, `snmp` | `snmpget -v3 -l noAuthNoPriv` | unauthenticated response or timeout |
| LDAP | 389/`ldap`, 636/`ldaps` | `ldapsearch -x` base DSE | anonymous bind attributes or refusal |

### Safety limits

- Confirmed inventory addresses only; still inside authorized scope.
- No credential store; no password or community guessing.
- No automatic Internet callbacks. DNS uses CHAOS names, not `example.com`.
- HTTP does not follow redirects (`--max-redirs 0`).
- SNMP walks and v2c `public`/`private` probes are out of the default profile.
- Authenticated AD/LDAP audit is out of scope until credentials exist.
- SMB is a conservative null-session list; `enum4linux-ng` is not invoked.
- Raspberry Pi default: one protocol-audit job (`WIRESCOPE_MAX_PROTOCOL_AUDIT_JOBS=1`)
  and sequential module execution (`WIRESCOPE_PROTOCOL_AUDIT_CONCURRENCY=1`).

### NSE policy

Protocol audits **do not** invoke Nmap Scripting Engine. There is no
`-sC`, `vuln`, `brute`, `exploit`, `dos`, or `auth` script allowlist because
NSE is not on this path. Dedicated tools are preferred.

`testssl.sh`, Nikto, and Nuclei exist only as `never-default` stubs. API
requests that name them receive `module_gated`. They cannot build commands.

### Resource locking

A protocol-audit job takes exclusive `audit:<audit_id>` and the
`protocol_audit` group (default max 1). It does **not** take
`interface:<name>`. Capture and Nmap keep the interface lock. Default worker
concurrency is still one, so a Pi will not overlap these jobs unless an
administrator raises both limits. Protocol probes can appear in a concurrent
capture if those limits are raised together; that is documented rather than
silently blocked.

### Cancellation and evidence

Cooperative cancellation terminates the subprocess group. The job ends
`cancelled`, not `failed`. Observations already persisted remain. Raw stdout
and stderr are filesystem artifacts (`protocol_tool_output`) hashed with
SHA-256. Job listings stay compact.

Re-processing upserts on
`(audit, asset, service, module, kind, dedupe_key)` and updates `last_seen`
instead of duplicating rows.

### What Milestone 5 consumes

Findings rules read `protocol_observations` kinds such as
`ssh_algorithms`, `tls_session`, `tls_certificate`, `http_response`,
`dns_flags`, `smb_null_session`, `snmp_unauthenticated`, and `ldap_rootdse`.
They must not parse raw `ssh-audit` or OpenSSL stdout. A missing tool is not
evidence that a protocol is absent.

Milestone 5 is implemented. See [FINDINGS_MODEL.md](FINDINGS_MODEL.md). The
findings job does not take `interface:<name>` and does not invoke protocol
tools.
