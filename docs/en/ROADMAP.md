# WireScope — Post-1.0 Roadmap

[Русский](../ROADMAP.md)

This roadmap describes development after the v1.0 feature freeze.

New work must preserve the core safety contracts: passive observation is not authorization for active scanning, active scope is operator-confirmed, external tools are executed without a shell, and conclusions remain traceable to retained evidence.

## v1.0 — Base network auditor

Status: **feature complete / frozen**.

The base line includes passive analysis, standalone PCAP capture, operator-confirmed active scope, Discovery / Standard / Deep profiles, conservative inventory correlation, protocol audits, findings with evidence, HTML/JSON/Markdown reports, audit diff, diagnostics, retention/recovery, web/kiosk UI, and appliance backup/restore.

After freeze, the v1.0 line receives defect fixes and release engineering rather than new major subsystems.

---

## v1.1 — PCAP Traffic Analysis

Status: **implementation complete; core live scenarios passed**.

v1.1 turns a retained PCAP into a standalone diagnostic source without starting another capture or contacting the network again.

Implemented capabilities include:

- deterministic retained-PCAP analysis;
- duration, frames, bytes, packets/s, and observed bandwidth;
- top talkers and a normalized communications graph;
- TCP retransmission/duplicate-ACK/out-of-order/reset/zero-window/SYN-handshake signals;
- DNS errors and latency statistics;
- ARP conflict/change hints;
- DHCP correlation;
- ICMP/ICMPv6;
- broadcast/multicast contributors;
- TLS/HTTP/QUIC/SMB protocol intelligence without payload decryption;
- cautious ACK RTT summaries;
- comparison of two persisted traffic-analysis results;
- canonical `traffic-analysis` JSON, readable text/Markdown, and web/kiosk presentation.

The communications graph is an **explicitly selected** topology input. WireScope never silently mixes the most recent capture into a network map.

---

## v1.2 — Network Topology

Status: **feature complete / closed**.

M11.1–M11.4 are implemented. Full automated regression is green, and the M11.4 hardening checkpoint was installed and exercised on an actual WireScope VM. The appliance remained healthy after upgrade, `/api/v1/ready` confirmed database/migrations/worker/capture dependencies, and a new Deep audit was used to validate the structural presentation. The resulting topology view was accepted for normal use.

The v1.2 goal is not merely to draw discovered IP addresses. It builds an explainable network map and tells the operator **which classes of topology claims are actually supported by the available evidence**.

### M11.1 — logical topology

Status: **complete**.

Canonical `network-topology` combines persisted evidence from inventory, ARP/ND, route/default-gateway context, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery, and an explicitly selected PCAP Traffic Analysis result.

The model keeps assets, interfaces, gateways/routers, subnet segments, infrastructure hints, external traffic endpoints, L2/L3/traffic relationships, confidence, and provenance separate. Sharing a subnet is never treated as proof of a direct physical L2 hop.

### M11.2 — operator visualization

Status: **complete**.

The web/kiosk UI provides:

- structural / infrastructure-first view;
- dedicated L2, L3, Traffic, and All Evidence views;
- subnet regions;
- retained-audit global topology;
- confidence filters;
- asset/edge details and findings;
- zoom/pan/fit;
- explicit PCAP overlay;
- topology JSON export;
- full structural-diagram SVG/PNG export;
- separate viewport SVG export;
- VLAN focus with VLAN JSON/SVG export;
- historical topology comparison.

Directed broadcasts, link-local noise, and PCAP-only external endpoints do not masquerade as normal infrastructure in the structural view.

### M11.3 — physical and L3 enrichment

Status: **complete**.

Implemented capabilities include:

- bounded traceroute/upstream evidence;
- read-only SNMPv2c/v3 enrichment;
- IF-MIB / IP-MIB / BRIDGE-MIB / Q-BRIDGE-MIB / LLDP-MIB;
- IPv4/IPv6 interface addresses and connected prefixes;
- ARP/IPv6 ND neighbor data;
- FDB/switch-port correlation;
- PVID/tagged/untagged VLAN membership;
- `access / trunk / hybrid / unknown` port semantics;
- LLDP chassis/port/management-address correlation;
- network-interface nodes and routed-interface relationships;
- conservative router classification;
- fail-visible `partial/source_errors` behavior for missing persisted management evidence.

A subnet learned from SNMP remains `active_scope=false`: management evidence may expand topology knowledge but never scanning authorization.

### M11.4 — topology hardening and evidence sufficiency

Status: **complete and live-tested on a WireScope VM**.

Implemented changes include:

- canonical evidence graph separated from presentation projection;
- `coverage` / claimability layer;
- `inventory`, `l3`, `l2`, `traffic`, `vlan`, `wifi`, and `hypervisor` domains reported as `sufficient / partial / missing`;
- explicit operator guidance about which stronger claims require additional evidence rather than a fake discovery percentage;
- persisted per-interface default routes and DHCP router-option evidence for multi-homed hosts;
- gateway projection only from exact persisted evidence, never `.1/.254/.11` guessing;
- optional read-only SSH topology provider for Linux/OpenWrt-like managed devices;
- fixed `ip/bridge/iw` SSH allowlist, strict host-key verification, no arbitrary remote command, and no shell execution;
- consume-once `0600` spool for SSH private-key/known_hosts material;
- fresh-credential requirement for SNMP/SSH management jobs;
- `ip neigh` treated as IP↔MAC identity evidence rather than physical-cable proof;
- FDB, bridge VLAN, and Wi-Fi association data used only when management-plane evidence supports the claim;
- source-health coverage for route-trace, SNMP, and SSH with sanitized fail-visible errors.

The v1.2 rule is simple: **when evidence is insufficient, WireScope reports the missing evidence instead of drawing a more confident diagram**.

### Live validation status

Validated on the installed WireScope VM:

- normal upgrade from the previous topology checkpoint;
- retained appliance state after upgrade;
- SQLite/migrations/worker readiness;
- `dumpcap` and `tshark` readiness;
- a new Deep audit on the real LAN interface;
- the structural topology presentation;
- absence of critical regressions that prevent normal topology use.

### Not live-validated in this environment

SNMP was not configured on the router used for this validation, so **SNMP/FDB/Q-BRIDGE/LLDP management enrichment is not claimed as live-validated**. Those paths are implemented and covered by automated regression; vendor-specific interoperability will be checked when suitable managed devices are available.

The same applies to live SSH VLAN/Wi-Fi enrichment on a suitable Linux/OpenWrt device.

This no longer blocks v1.2 closure: topology correctly reports missing management evidence through `coverage` and does not invent VLAN/FDB/Wi-Fi structure when those sources are unavailable.

See [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md) for the full evidence contract.

---

## v1.3 — Global Correlation Analysis

Status: **next stage**.

Goal: combine Deep/active audit results, selected PCAP Traffic Analysis, findings, and Network Topology into one deterministic analytical package.

The first required correlation rules are:

1. **Asset ↔ traffic identity** — exact IP/MAC, never hostname-only merge.
2. **Service ↔ observed traffic** — which discovered services/ports were actually seen in the selected capture.
3. **Finding ↔ traffic relevance** — whether a finding belongs to an asset/service participating in observed traffic; absence of a relationship means `uncorrelated`, not “irrelevant”.
4. **Inventory ↔ Traffic coverage** — inventory assets absent from capture and traffic endpoints that cannot be linked to inventory.
5. **Internal ↔ external communications** — external endpoints associated with specific internal assets with protocol/port/packet-byte context.
6. **Infrastructure consistency** — compare gateway/DHCP/DNS observations across environment, passive evidence, and topology.
7. **Evidence quality** — partial/missing input propagates to the global result; correlation never raises confidence above the source evidence.

Outputs:

- canonical `global-analysis` JSON;
- deterministic rule IDs;
- evidence references across audits/assets/services/findings/traffic/topology;
- readable Russian operator summary;
- warnings and partial state for incomplete sources;
- reproducible offline output without external AI.

Global Analysis does **not** re-read PCAP or start a scanner. It consumes persisted normalized data.

---

## v1.4 — AI-assisted Global Analysis

Optional AI analysis may be added only on top of deterministic `global-analysis`.

Constraints:

- AI does not replace deterministic correlation;
- raw PCAP is not sent to an external provider by default;
- the operator explicitly controls which normalized data may leave the appliance;
- API keys stay backend-side;
- AI output is an analytical conclusion/hypothesis, not an automatic WireScope finding;
- output must reference evidence/correlation IDs.

External APIs and local/offline models can share an `AIProvider` abstraction.

---

## Later ideas

Non-blocking future work includes PDF export, additional protocol modules, local/controlled CVE enrichment, scheduled audits, longer traffic baselines, cross-site topology history, hypervisor-specific topology providers, vendor-specific management-plane adapters, and a broader distro/architecture/tshark compatibility matrix.

## Current next step

**v1.3 — Global Correlation Analysis.**

First implementation slice: persisted inventory/report source + explicitly selected `traffic-analysis` + canonical `network-topology` → deterministic `global-analysis`, starting with exact asset identity, observed service use, inventory-vs-traffic coverage, and external-endpoint correlation.