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

Implemented capabilities include deterministic retained-PCAP analysis, duration/frames/bytes/packets-per-second/bandwidth, top talkers and communications graph, TCP health, DNS latency/errors, ARP conflict hints, DHCP, ICMP/ICMPv6, broadcast/multicast contributors, TLS/HTTP/QUIC/SMB metadata, cautious ACK RTT, persisted-result comparison, canonical JSON, text/Markdown exports, and web/kiosk presentation.

The communications graph is an **explicitly selected** topology input. WireScope never silently mixes the latest capture into a topology.

---

## v1.2 — Network Topology

Status: **feature complete / closed**.

M11.1–M11.4 are implemented. Full automated regression is green and M11.4 was installed and exercised on a WireScope VM. The appliance remained healthy after upgrade, `/api/v1/ready` confirmed database/migrations/worker/capture dependencies, and a new Deep audit validated the structural presentation.

The v1.2 goal is not merely to draw discovered addresses. It builds an explainable map and exposes which classes of topology claims are actually supported by evidence.

### M11.1 — logical topology

Status: **complete**.

Canonical `network-topology` combines persisted inventory, ARP/ND, route/default-gateway context, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery, and an explicitly selected PCAP Traffic Analysis. Assets, interfaces, routers/gateways, segments, infrastructure hints, external endpoints, L2/L3/traffic relationships, confidence, and provenance remain distinct. Sharing a subnet never proves a direct L2 link.

### M11.2 — operator visualization

Status: **complete**.

The web/kiosk UI provides structural/infrastructure-first presentation, L2/L3/Traffic/All Evidence views, subnet regions, retained-audit global topology, confidence filters, details/findings, zoom/pan/fit, explicit PCAP overlay, JSON and SVG/PNG exports, VLAN focus/export, and historical topology comparison.

Directed broadcast, link-local noise, and PCAP-only external endpoints do not masquerade as normal infrastructure.

### M11.3 — physical and L3 enrichment

Status: **complete**.

Implemented capabilities include bounded traceroute/upstream evidence, read-only SNMPv2c/v3, IF-MIB/IP-MIB/BRIDGE-MIB/Q-BRIDGE-MIB/LLDP-MIB, IPv4/IPv6 interface/prefix evidence, ARP/ND, FDB/switch-port correlation, VLAN membership and access/trunk/hybrid semantics, LLDP correlation, interface/routed-interface nodes, conservative router classification, and fail-visible `partial/source_errors`.

SNMP-observed subnets remain `active_scope=false`: management evidence may expand topology knowledge but never scanning authorization.

### M11.4 — topology hardening and evidence sufficiency

Status: **complete and live-tested on a WireScope VM**.

Implemented changes include:

- canonical evidence graph separated from presentation projection;
- `coverage` / claimability layer;
- `inventory`, `l3`, `l2`, `traffic`, `vlan`, `wifi`, and `hypervisor` domains reported as `sufficient / partial / missing`;
- explicit missing-evidence guidance instead of a fake discovery percentage;
- persisted per-interface default routes and DHCP router-option evidence;
- gateway projection from exact evidence only, never `.1/.254/.11` guessing;
- optional read-only SSH topology provider for Linux/OpenWrt-like devices;
- fixed `ip/bridge/iw` allowlist, strict host-key verification, no arbitrary command;
- consume-once `0600` secret spool;
- fresh credentials for SNMP/SSH jobs;
- `ip neigh` used for IP↔MAC identity but not physical-cable claims;
- FDB/bridge VLAN/Wi-Fi evidence used only when management evidence supports it;
- source-health for route-trace, SNMP, and SSH;
- omitted expected job-backed artifacts make topology `partial` with sanitized errors.

The v1.2 rule is simple: **when evidence is insufficient, WireScope reports the missing evidence instead of drawing a more confident diagram**.

### Live validation status

Normal upgrade, appliance-state retention, SQLite/migrations/worker readiness, `dumpcap`/`tshark` readiness, a fresh Deep audit, and structural topology presentation were validated on the installed WireScope VM.

SNMP/FDB/Q-BRIDGE/LLDP management enrichment and SSH VLAN/Wi-Fi enrichment are not claimed as live-validated because no suitable managed device was available in the current environment. These paths remain covered by automated regression and do not block v1.2 closure.

See [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md).

---

## v1.3 — Global Correlation Analysis

Status: **implementation complete in code; automated validation green; live validation on a WireScope VM remains**.

Goal: combine Deep/active audit data, an explicitly selected PCAP Traffic Analysis, findings, and Network Topology into one deterministic analytical package that explains relationships between persisted results rather than exposing four unrelated reports.

Required correlation domains:

1. **Asset ↔ traffic identity** — exact IP/MAC only, never hostname-only merge.
2. **Service ↔ observed traffic** — inventory services/ports visible in the selected capture.
3. **Finding ↔ traffic relevance** — whether a finding belongs to an asset/service participating in observed traffic; no relationship means `uncorrelated`, not “irrelevant”.
4. **Inventory ↔ Traffic coverage** — inventory assets outside capture visibility and traffic endpoints without inventory identity.
5. **Internal ↔ external communications** — globally routable external endpoints associated with exact-correlated internal assets.
6. **Infrastructure consistency** — gateway/DHCP/DNS evidence across environment, passive, traffic, and topology sources.
7. **Evidence quality** — partial/missing inputs propagate and confidence is never raised beyond source evidence.

### Slice 1 — deterministic correlation core ✓

Implemented:

- dedicated `global_analysis` package;
- canonical `global-analysis` v1;
- offline preview API;
- exact IP/MAC identity and explicit hostname non-merge;
- deterministic correlation IDs and versioned rule IDs;
- conservative endpoint classes `internal_asset / internal_segment / external_global / private_unknown / special / unknown`;
- pair-level service-use correlation;
- finding↔traffic relevance;
- inventory-vs-capture visibility;
- internal asset ↔ globally routable external endpoint correlation;
- separate `private_unknown` handling;
- propagation of topology/report partial state and identity conflicts.

The current `traffic-analysis` v1 aggregates destination ports per communication pair. Service-use therefore uses `observed_pair_destination_port`: it confirms that the service port was observed within a pair containing the asset but does not claim which endpoint owned the socket without directional evidence.

### Slice 2 — durable result + cross-source consistency ✓

Implemented:

- durable `global_analysis` worker job;
- `POST /api/v1/audits/{audit_id}/global-analysis`;
- persisted `global_analysis_result` / `global-analysis` v1 / `audit` retention;
- namespaced `audit.summary.global_analysis`;
- gateway/DHCP/DNS consistency rules;
- safe evidence lineage across audit/assets/services/findings/traffic/topology;
- artifact references include ID/type/hash/schema/timestamp but no filesystem path;
- deterministic Russian `operator_summary`;
- preview and durable execution share one correlation runtime;
- no scanner, PCAP re-read, or network I/O.

### Slice 3 — history, rebuild, exports, and operator GUI ✓

Implemented:

- durable Global Analysis history per audit;
- result reading only for a valid completed `global_analysis_result`;
- immutable rebuild as a new job/artifact with `rebuild_of_job_id`;
- rebuild requires a completed durable result from the same audit and the same selected Traffic Analysis;
- JSON/TXT/Markdown exports rendered from persisted canonical JSON;
- dedicated operational audit action `global_analysis.generate`;
- a separate web/kiosk workspace without altering the core audit pipeline;
- explicit audit and completed Traffic Analysis selection;
- run/progress/cancel for auditor;
- history/read/export for auditor and viewer;
- summary, infrastructure consistency, coverage/source health, finding relevance, external communications, warnings, and evidence lineage;
- explicit `node --check` for the new JavaScript in CI.

### Automated validation

At the Slice 3 checkpoint the full CI passed:

- Python compile;
- Global Analysis JavaScript syntax check;
- **494 tests passed, 3 deselected**;
- wheel build;
- installed-wheel smoke importing both `topology` and `global_analysis` outside the source tree.

Subsequent hardening is limited to rebuild-source validation and operational audit action; branch CI remains the required gate before live installation.

See [GLOBAL_ANALYSIS_MODEL.md](GLOBAL_ANALYSIS_MODEL.md) and [API.md](API.md).

### Remaining work before v1.3 closure

Only live validation on an installed WireScope VM remains:

- upgrade through the normal appliance path;
- verify `/api/v1/ready`, worker/database/migrations/capture dependencies;
- select an existing/new Deep audit and retained Traffic Analysis;
- execute durable Global Analysis;
- inspect canonical output, `partial/source_health`, consistency, and evidence lineage against real persisted data;
- validate the operator GUI, history, immutable rebuild, and JSON/TXT/Markdown exports;
- create the v1.3 checkpoint/tag after successful live validation.

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

**v1.3 — live validation and release closure.**

Slices 1–3 are implemented. The next step is to upgrade the WireScope VM through the normal path and validate durable Global Analysis, history/rebuild/exports, and the operator GUI against real persisted Deep/Traffic Analysis data. After a successful live check, v1.3 can be checkpointed/tagged and development can move to the separate v1.4 AI-assisted layer.
