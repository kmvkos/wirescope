# Network Topology Model

[Русский](../TOPOLOGY_MODEL.md)

WireScope builds topology as an auditor, not as a diagram generator. The canonical graph retains observed and confirmed evidence, while the presentation layer separately decides what belongs in the structural map.

The core rule is: **a missing relationship is never drawn from a guess**. A shared subnet, similar hostname, or observed traffic does not prove a physical L2 hop, a specific switch port, VLAN membership, Wi-Fi association, or VM-to-hypervisor placement.

## Status

Network Topology v1.2 is complete.

M11.4 was installed and exercised on an actual WireScope VM: the normal upgrade path completed successfully, `/api/v1/ready` confirmed database/migrations/worker/dumpcap/tshark health, and a new Deep audit was used for live validation of the structural topology presentation. No critical regression preventing normal topology use was found.

SNMP was not configured on the validation router. Therefore SNMP/FDB/Q-BRIDGE/LLDP management enrichment is **not claimed as live-validated**. It is implemented and covered by automated regression; vendor-specific interoperability remains an operational validation task when suitable managed devices are available.

The same applies to live SSH VLAN/Wi-Fi enrichment, which requires a suitable managed Linux/OpenWrt device and a dedicated read-only account.

## Model layers

```text
persisted evidence
      ↓
canonical topology
      ↓
evidence coverage / claimability
      ↓
structural · L2 · L3 · Traffic · all evidence
```

Canonical topology remains the source of truth. Structural filtering does not delete raw/evidence nodes: directed broadcasts, link-local endpoints, and PCAP-only external endpoints can be hidden or grouped in the main view while remaining available in the corresponding evidence/traffic layers and JSON.

## Evidence sufficiency

Topology responses include a `coverage` block. It does not estimate what percentage of the real network has been discovered. It answers a stricter question: **which classes of claims are supported by the retained evidence right now**.

Domains:

- `inventory` — confirmed assets;
- `l3` — subnet/gateway/router relationships;
- `l2` — LLDP/CDP/FDB/switch-port or equivalent physical-adjacency evidence;
- `traffic` — communication edges from an explicitly selected persisted Traffic Analysis result;
- `vlan` — VLAN membership/PVID/tagged/untagged evidence;
- `wifi` — AP/client association from the management plane;
- `hypervisor` — out-of-band guest-to-host evidence.

Domain status values:

- `sufficient` — enough evidence exists for that class of claim;
- `partial` — useful observations exist, but they do not describe the class completely;
- `missing` — WireScope has no evidence that supports that class of claim.

`missing` does not mean the object or relationship does not exist in the real network. A missing Wi-Fi association table, for example, means only that WireScope cannot prove which AP a client is attached to.

`coverage` is not a security score and is not a percentage estimate of the real network discovered by WireScope.

## Structural presentation

The default map is an infrastructure-first projection rather than a direct drawing of every node in the canonical graph.

Structural view emphasizes subnet regions, gateway/router evidence, network devices, assets, and evidence-backed infrastructure relationships.

The following should not visually masquerade as ordinary infrastructure hosts:

- subnet-directed broadcast addresses;
- uncorrelated link-local IPv6 noise;
- multicast/broadcast service endpoints;
- PCAP-only external endpoints.

Traffic and raw evidence remain available as separate views.

## L3 and multi-interface hosts

WireScope persists route context for the specific audit interface. On a multi-homed appliance, a host-wide default route through another interface is not treated as the gateway of the selected audit network.

Accepted interface-specific gateway sources include:

- a persisted default route for that interface;
- a DHCP lease/router option for that interface;
- read-only SNMP/SSH management evidence;
- bounded route-trace evidence inside an authorized active context.

Gateway addresses are never guessed from patterns such as `.1`, `.254`, or `.11`.

A management-discovered connected subnet may be added as topology evidence but remains `active_scope=false`. Additional routing knowledge is never additional active-scan authorization.

## L2

A physical link is emitted only when evidence actually describes adjacency or port mapping, for example:

- LLDP/CDP;
- bridge/FDB plus managed port context;
- SNMP BRIDGE/Q-BRIDGE/LLDP;
- read-only SSH `bridge` data;
- another provider with equivalent evidence.

ARP/ND or `ip neigh` can support IP-to-MAC identity, but **do not prove a direct physical cable** between endpoints.

An unmanaged switch without management/LLDP evidence may remain invisible. WireScope does not create a synthetic switch node merely because several hosts share a subnet.

## VLAN

VLAN membership is projected conservatively.

Allowed cases:

1. the FDB entry contains an exact VLAN ID — that VLAN may be associated with the endpoint;
2. the FDB entry has no VLAN ID, but the port is unambiguously a single-VLAN access port — PVID/untagged membership may be used;
3. a multi-VLAN trunk/hybrid port without an exact FDB VLAN — WireScope **does not choose one VLAN** for the endpoint.

Port evidence retains `port_mode`, `pvid`, `tagged_vlans`, `untagged_vlans`, `vlan_ids`, and the source of the decision.

A passively observed 802.1Q tag is real VLAN evidence. Untagged access traffic does not prove a VLAN ID.

## Traffic overlay

PCAP is not mixed into topology automatically. The operator explicitly selects a persisted Traffic Analysis result.

The Traffic layer shows only communication visible from that capture point. External PCAP endpoints do not become infrastructure devices in the structural map merely because traffic was observed.

Likewise, an inventory asset absent from a selected PCAP is not assumed absent from the real network; every capture has its own visibility boundary.

## Read-only management sources

### SNMP

`POST /api/v1/audits/{audit_id}/topology/snmp`

Uses read-only SNMPv2c/v3. The target must be inside the operator-confirmed scope of the same audit interface.

Supported standard evidence includes IF-MIB/IP-MIB, BRIDGE-MIB/Q-BRIDGE-MIB, and LLDP-MIB where the device actually exposes those trees.

SNMP may provide:

- interface metadata;
- IPv4/IPv6 addresses and prefixes;
- ARP/ND;
- FDB;
- PVID/VLAN membership;
- switch-port mapping;
- LLDP neighbours.

A missing MIB subtree becomes `capability=false/empty`; it is not reported as a successful check and does not invalidate the whole topology operation.

Credentials are handed to the worker through an ephemeral spool and are not stored in canonical topology/job evidence as plaintext.

### SSH

`POST /api/v1/audits/{audit_id}/topology/ssh`

The SSH provider targets Linux/OpenWrt-like managed devices and is not a generic remote shell.

Contract:

- target must be inside confirmed active scope;
- the mutating endpoint requires the `auditor` role;
- strict host-key verification is mandatory through supplied `known_hosts` material;
- private key/known_hosts material is written only to a `0600` consume-once runtime spool and is not persisted in SQLite/evidence;
- no arbitrary operator command field exists;
- `shell=True` is never used;
- remote argv is fixed by the provider.

Current allowlist:

```text
ip -j addr show
ip -j route show table main
ip -j neigh show
bridge -j fdb show
bridge -j vlan show
iw dev
iw dev <validated-interface> station dump
```

An unavailable command becomes a capability/warning and does not invalidate other evidence collected successfully.

Queued cancellation deletes the credential spool immediately. A running handler deletes it from `finally`. SNMP/SSH management jobs cannot be retried with an old credential reference; a fresh enrichment request with fresh credentials is required.

## Wi-Fi and hypervisor context

Wi-Fi attachment is considered proven only when association evidence comes from a managed AP/router, for example `iw station dump` or an equivalent provider.

An ordinary LAN scan cannot prove:

```text
physical host → local hypervisor → specific VM
```

That claim requires an out-of-band hypervisor/API/helper source. A VMware OUI or similar MAC pattern can be a hint, not proof of placement.

## Source health

If a job-backed persisted route/SNMP/SSH artifact should participate in topology but a decorator cannot include it, the map remains available while becoming explicitly partial:

```json
{
  "partial": true,
  "source_errors": [
    {
      "component": "ssh-topology",
      "code": "artifact_unavailable"
    }
  ]
}
```

Exception text, filesystem paths, and credentials are not exposed through `source_errors`.

A legacy/jobless management artifact is not declared broken when WireScope cannot reliably determine whether that artifact should be the current source.

## Historical topology

Topology comparison consumes persisted evidence only and performs no network I/O.

Cross-audit identity remains conservative:

- MAC is stronger than IP;
- exact IP may be used when there is no stronger conflict;
- hostname alone does not prove one identity;
- an unstable audit-local UUID should not create a false `removed + added` pair when stable identity is supported.

## Export

Two SVG exports serve different purposes:

- **full structural diagram** — renders the whole current structural topology for export;
- **current viewport SVG** — preserves current filters/zoom/pan for diagnostic use.

PNG is rendered from the structural diagram. JSON remains the full canonical representation rather than only what happens to be visible in the viewport.

## API

Main endpoints:

```text
GET  /api/v1/audits/{audit_id}/topology
GET  /api/v1/topology/global
GET  /api/v1/audits/{audit_id}/topology/compare?against={baseline_audit_id}
POST /api/v1/audits/{audit_id}/topology/snmp
POST /api/v1/audits/{audit_id}/topology/ssh
```

`GET .../topology` may accept `traffic_analysis_job_id` for an explicitly selected PCAP overlay.

Topology comparison consumes persisted evidence only and does not launch a scanner, SNMP, SSH, or traceroute operation.

## Limits

An ordinary LAN audit cannot reliably reconstruct every physical device and relationship. In particular:

- an unmanaged switch without LLDP/FDB management evidence may remain invisible;
- NAT/routing boundaries can hide internal endpoints;
- Wi-Fi attachment requires association data from the AP/router;
- VM-to-hypervisor placement requires hypervisor/API/helper evidence;
- PCAP shows only what was visible at the capture point;
- topology from one subnet does not prove a global multi-site structure;
- vendor-specific SNMP/CLI behavior may require a dedicated adapter after live interoperability testing.

WireScope reports these limits through `coverage`, warnings, and `partial/source_errors` instead of compensating with heuristic links.