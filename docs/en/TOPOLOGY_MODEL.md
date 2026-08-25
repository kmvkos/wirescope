# Network Topology Model

[Русский](../TOPOLOGY_MODEL.md)

WireScope builds topology as an auditor, not as a diagram generator. The canonical graph retains observed and confirmed evidence, while the presentation layer separately decides what belongs in the structural map.

The core rule is: **a missing relationship is never drawn from a guess**. A shared subnet, similar hostname, or observed traffic does not prove a physical L2 hop, a specific switch port, VLAN membership, Wi-Fi association, or VM-to-hypervisor placement.

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

Topology responses include a `coverage` block. It does not attempt to estimate a percentage of the real network that has been discovered. It answers a stricter question: **which classes of claims are supported by the retained evidence right now**.

Domains:

- `inventory` — confirmed assets;
- `l3` — subnet/gateway/router relationships;
- `l2` — LLDP/CDP/FDB/switch-port or equivalent physical adjacency evidence;
- `traffic` — communication edges from an explicitly selected persisted Traffic Analysis result;
- `vlan` — VLAN membership/PVID/tagged/untagged evidence;
- `wifi` — AP/client association from the management plane;
- `hypervisor` — out-of-band guest-to-host evidence.

Domain status values:

- `sufficient` — enough evidence exists for that class of claim;
- `partial` — useful observations exist, but they do not describe the class completely;
- `missing` — WireScope has no evidence that supports that class of claim.

`missing` does not mean the object or relationship does not exist in the real network. For example, a missing Wi-Fi association table means only that WireScope cannot prove which AP a client is attached to.

## L3 and multi-interface hosts

WireScope persists route context for the specific audit interface. On a multi-homed appliance, a host-wide default route through another interface is not treated as the gateway of the selected audit network.

Accepted interface-specific gateway sources include:

- a persisted default route for that interface;
- a DHCP lease/router option for that interface;
- read-only SNMP/SSH management evidence;
- bounded route-trace evidence inside an authorized active context.

Gateway addresses are never guessed from patterns such as `.1`, `.254`, or `.11`.

## L2

A physical link is emitted only when evidence actually describes adjacency or port mapping, for example:

- LLDP/CDP;
- bridge/FDB plus managed port context;
- SNMP BRIDGE/Q-BRIDGE/LLDP;
- read-only SSH `bridge` data;
- a future provider with equivalent evidence.

ARP/ND or `ip neigh` can support IP-to-MAC identity, but **do not prove a direct physical cable** between endpoints.

## VLAN

VLAN membership is projected conservatively.

Allowed cases:

1. the FDB entry contains an exact VLAN ID — that VLAN may be associated with the endpoint;
2. the FDB entry has no VLAN ID, but the port is unambiguously a single-VLAN access port — PVID/untagged membership may be used;
3. a multi-VLAN trunk/hybrid port without an exact FDB VLAN — WireScope **does not choose one VLAN** for the endpoint.

Port evidence retains `port_mode`, `pvid`, `tagged_vlans`, `untagged_vlans`, `vlan_ids`, and the source of the decision.

## Traffic overlay

PCAP is not mixed into topology automatically. The operator explicitly selects a persisted Traffic Analysis result.

The Traffic layer shows only communication visible from that capture point. External PCAP endpoints do not become infrastructure devices in the structural map merely because traffic was observed.

## Read-only management sources

### SNMP

`POST /api/v1/audits/{audit_id}/topology/snmp`

Uses read-only SNMPv2c/v3. The target must be inside the operator-confirmed scope of the same audit interface. Credentials are handed to the worker through an ephemeral spool and are not stored in canonical topology/job evidence as plaintext.

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

Queued cancellation deletes the credential spool immediately. A running handler deletes it from `finally`. SNMP/SSH management jobs cannot be retried with old parameters: a fresh enrichment request with fresh credentials is required.

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

## API

Main endpoints:

```text
GET  /api/v1/audits/{audit_id}/topology
GET  /api/v1/topology/global
GET  /api/v1/audits/{audit_id}/topology/compare?against={baseline_audit_id}
POST /api/v1/audits/{audit_id}/topology/snmp
POST /api/v1/audits/{audit_id}/topology/ssh
```

Topology comparison consumes persisted evidence only and does not launch a scanner, SNMP, SSH, or traceroute operation.

## Limits

An ordinary LAN audit cannot reliably reconstruct every physical device and relationship. In particular:

- an unmanaged switch without LLDP/FDB management evidence may remain invisible;
- NAT/routing boundaries can hide internal endpoints;
- Wi-Fi attachment requires association data from the AP/router;
- VM-to-hypervisor placement requires hypervisor/API/helper evidence;
- PCAP shows only what was visible at the capture point;
- topology from one subnet does not prove a global multi-site structure.

WireScope reports these limits through `coverage`, warnings, and `partial/source_errors` instead of compensating with heuristic links.
