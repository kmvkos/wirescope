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
