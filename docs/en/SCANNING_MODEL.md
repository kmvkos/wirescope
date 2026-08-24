# WireScope scanning model

[Русский](../SCANNING_MODEL.md) · **English**

WireScope separates network auditing into passive observation, active inventory, and service-aware protocol checks. Findings sit above those layers and are not part of the scanner/provider layer itself.

## Core rule: observed is not authorized

Passive analysis may reveal IP addresses, gateways, VLANs, DHCP servers, or LLDP/CDP neighbors. Environment discovery may reveal connected routes. Those are **observed network facts**.

They do not automatically become active-scan scope.

Before Nmap starts, the operator confirms targets and the backend stores an immutable authorized-scope snapshot.

```text
environment + passive evidence
            ↓
      scope proposal
            ↓
   operator confirmation
            ↓
 confirmed scope snapshot
            ↓
       Nmap discovery
            ↓
      asset inventory
            ↓
    protocol audits
```

Frontend validation is not trusted as the final boundary. The worker validates the stored scope again before invoking the scanner.

## Scope format

`engine/scope.py` uses Python's `ipaddress` module.

Accepted inputs are:

- one IPv4 address;
- one IPv6 address;
- IPv4 CIDR;
- IPv6 CIDR;
- multiple mixed targets.

Targets are canonicalized. Duplicates and addresses already covered by a wider target are removed.

Unspecified and multicast ranges are rejected, including:

```text
0.0.0.0/0
::/0
224.0.0.0/4
IPv6 multicast equivalents
```

Scope size is calculated **before** a job is created.

## Default target caps

The defaults are sized for a small appliance and an ordinary LAN audit:

| Profile | IPv4 cap | Rough CIDR equivalent |
| --- | ---: | --- |
| Discovery | 4096 | `/20` |
| Standard | 1024 | `/22` |
| Deep | 256 | `/24` |

IPv6 has its own 256-address cap. WireScope does not attempt to brute-force an IPv6 `/64`.

An administrator can deliberately raise these limits with `WIRESCOPE_ALLOW_LARGE_SCOPES=true` and the matching `WIRESCOPE_*_MAX_TARGETS` settings. Unspecified-network prohibitions still apply.

## Interface and route validation

A target being inside a CIDR is not enough for active discovery.

WireScope checks that:

- the selected interface exists;
- it passes interface policy;
- the link is UP;
- `ip route get` for the target resolves to the selected `dev`;
- a source address exists for the target address family;
- a VLAN subinterface already exists if one is selected.

Route context is retained with the confirmed scope: source address, gateway, interface, family, and directly-connected/routed state.

A capture NIC may have no L3 address and still perform passive capture. Active discovery requires a real L3 path: an address on the NIC, an already configured VLAN subinterface such as `eth0.10`, or another explicitly confirmed and routable target set.

The active-discovery path does not create VLAN subinterfaces itself.

## Nmap profiles

Users choose a profile, not raw command-line flags. Default timing is **T3**. T5 is not used.

### Discovery

Designed to answer “which hosts respond?” quickly.

Directly connected IPv4 can use ARP discovery when raw privileges are available. Routed IPv4 uses ICMP/TCP discovery probes. IPv6 uses neighbor discovery when possible and TCP probes otherwise.

There is no service port scan, `-sV`, or OS detection in this profile.

### Standard

The normal inventory profile:

- host discovery;
- TCP top 1000;
- `-sV --version-intensity 5`;
- OS detection when the process already has the required privileges;
- curated UDP ports:
  `53,67,68,69,111,123,137,161,162,500,623,1900,4500,5353,5355`.

### Deep

The heavier profile:

- host discovery;
- TCP `1-65535`;
- `--version-intensity 7`;
- OS detection when available;
- expanded UDP coverage.

Deep still does not enable NSE, `-sC`, `vuln`, brute, exploit, auth, or DoS scripts.

## Nmap provider

`providers/nmap.py` is the only Nmap execution path.

It:

- locates the binary and version;
- detects raw-socket capability without elevating the process;
- builds argv arrays;
- writes validated targets to an internal `0600` file used with `-iL`;
- requests XML with `-oX`;
- stores XML as an evidence artifact;
- honors timeout and cooperative cancellation;
- returns normalized hosts, services, and OS hints.

Without raw privileges:

```text
SYN / ARP / OS / UDP unavailable
             ↓
        TCP connect -sT
             ↓
 skipped capabilities recorded
```

WireScope does not launch one Nmap process per host. A scan uses a small number of stage-oriented processes over the target list.

Default `WIRESCOPE_MAX_ACTIVE_DISCOVERY_JOBS=1`.

## Host state

No ICMP echo is not the same as “host down”.

Inventory states are:

- `observed` — passive evidence only;
- `responsive` — Nmap reported the host up;
- `unresponsive` — a singleton target did not respond;
- `unknown` — state could not be determined reliably.

For a large CIDR, WireScope does not materialize an asset row for every silent address.

Nmap failure is a job error, not “0 hosts found”.

## Inventory

An asset is not globally keyed by one IP address.

Inventory can retain:

- MAC and vendor;
- addresses with provenance;
- names with provenance;
- services;
- OS hints;
- device-class hints;
- first/last seen timestamps.

Services are unique per asset by `(protocol, port)`.

### Passive/active correlation

Correlation order is:

1. exact MAC;
2. exact IP.

If MAC identity points to asset A while IP identity points to asset B, WireScope records the conflict rather than silently merging them.

Names from PTR, DHCP, mDNS, LLMNR, NBNS, and Nmap retain provenance.

### Vendor lookup

OUI lookup is local, using:

```text
/usr/share/ieee-data/oui.txt
```

or the bundled subset.

WireScope does not make one external HTTP request per MAC address.

### OS and device class

OS matches and device classes are hints, not confirmed facts.

Device-class values include:

- `server-like`;
- `workstation-like`;
- `network-device-like`;
- `printer-like`;
- `iot-like`;
- `unknown`.

## Resource locking

Active discovery takes:

- `interface:<name>`;
- resource group `active_discovery`.

This prevents capture and Nmap from sharing the same interface under the standard configuration.

The default active-discovery limit is one job.

## Network impact

`Standard` on a `/24` at T3 is the normal LAN scenario.

`Deep` is considerably noisier and slower because it scans the full TCP range and more UDP ports. Its default scope cap is therefore 256 addresses.

Cancellation terminates the Nmap process group and marks the job `cancelled`. Valid results already committed by completed stages may remain in inventory.

## Protocol audits

After active inventory, WireScope can inspect specific discovered services.

```text
inventory service
      ↓
registry predicate match
      ↓
check authorized address
      ↓
provider argv
      ↓
external tool
      ↓
parser
      ↓
normalized protocol observation
      ↓
evidence + SQLite
```

A protocol audit is not itself a vulnerability scanner. It produces structured facts for the findings engine.

## Module contract

Each module under `protocol_audits/modules/` declares:

- port/transport/service/product/tunnel predicates;
- required tool;
- optional minimum version;
- safety class: `safe`, `gated`, or `never-default`;
- argv builder;
- parser with no SQLite dependency;
- timeout budget;
- normalized observation kinds.

Adding a module requires registry registration rather than changes to the orchestration core.

## Current protocol modules

| Module | Tool | Recorded data |
| --- | --- | --- |
| SSH | `ssh-audit` | banner, KEX, host-key, cipher, MAC algorithms |
| TLS | `openssl s_client` | protocol, cipher, certificate metadata, verify code |
| HTTP | `curl` | status, selected headers, HTML title |
| DNS | `dig` | CHAOS identity and DNS flags |
| SMB | `smbclient -N -L` | null session accepted/refused |
| SNMP | `snmpget -v3 -l noAuthNoPriv` | unauthenticated response/timeout |
| LDAP | `ldapsearch -x` | anonymous base DSE / refusal |

## Protocol-audit safety limits

- Confirmed inventory addresses only, still inside authorized scope.
- No credential store.
- No password or community-string guessing.
- No SNMP walk.
- HTTP does not automatically follow redirects (`--max-redirs 0`).
- SMB enumeration is limited to a null-session list probe.
- Authenticated AD/LDAP auditing is not implemented yet.
- Checks do not require automatic Internet callbacks.

Defaults:

```text
WIRESCOPE_MAX_PROTOCOL_AUDIT_JOBS=1
WIRESCOPE_PROTOCOL_AUDIT_CONCURRENCY=1
WIRESCOPE_PROTOCOL_AUDIT_TIMEOUT_SECONDS=20
```

## NSE policy

The protocol-audit path does not use Nmap Scripting Engine.

There is no `-sC`, and there is no `vuln/brute/exploit/dos/auth` script allowlist because NSE is not the provider model on this path.

`testssl.sh`, Nikto, and Nuclei exist only as `never-default` stubs. They cannot build commands for a normal API request.

## Tool errors

A protocol observation may represent:

- `tool_unavailable`;
- timeout;
- cancellation;
- malformed output;
- provider failure;
- protocol-specific negative response.

Those states are deliberately distinct.

For example:

```text
smbclient is missing
```

does not mean:

```text
SMB null sessions are refused
```

and certainly does not mean that SMB is absent.

## Evidence and re-runs

Raw protocol-provider stdout/stderr is stored as a `protocol_tool_output` evidence artifact with SHA-256.

Normalized observations are upserted using stable deduplication identity rather than appended forever on every re-run.

The findings engine consumes normalized observations, not raw provider output.

See [FINDINGS_MODEL.md](FINDINGS_MODEL.md).
