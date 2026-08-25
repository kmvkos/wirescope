# WireScope — Post-1.0 Roadmap

[Русский](../ROADMAP.md)

This roadmap starts after the v1 feature freeze. New capabilities must preserve the v1 safety contracts: observed traffic is not authorization for active scanning, active scope is operator-confirmed, external tools are executed without a shell, and retained evidence remains reproducible.

## v1.0 — Base network auditor

Status: **feature complete / frozen**.

The release includes passive discovery, standalone PCAP capture, confirmed Discovery/Standard/Deep active scope, inventory, safe protocol audits, findings, HTML/JSON/Markdown reports, audit diff, evidence viewer, diagnostics, retention/retry, web/kiosk UI, report deletion, and full deletion of inactive audits.

## v1.1 — PCAP Traffic Analysis

Status: **implementation complete; core live smoke scenarios passed**.

Implemented milestones cover deterministic analysis of retained PCAP, a normalized communications graph, TCP/DNS/ARP/DHCP/ICMP diagnostics, protocol intelligence, defensible ACK RTT summaries, and persisted capture-to-capture comparison. Traffic Analysis does not start a new capture and remains explicit input to topology rather than a competing network model.

## v1.2 — Network Topology

Status: **M11.1–M11.4 implementation complete; full automated regression is green, live-network validation of the hardening checkpoint remains**.

Goal: render a useful map of the observed network while exposing provenance, confidence, and whether the retained evidence is actually sufficient for each class of topology claim.

### M11.1 — logical topology

Status: **implemented and live-tested with Deep audit + explicit PCAP overlay**.

Canonical topology combines inventory, ARP, interface-specific routing context, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery, and explicitly selected PCAP communications. Physical, routed, traffic, and inferred relationships remain distinct.

### M11.2 — interactive visualization

Status: **implemented with Chromium regression for layout, filters, focus/zoom and exports**.

The web/kiosk UI includes subnet regions, global retained-audit view, L2/L3/Traffic filters, confidence filters, asset/edge details, findings, explicit PCAP overlay, JSON/SVG/PNG export, and evidence-backed VLAN focus.

### M11.3 — deeper physical and L3 topology

Status: **implemented; management-plane live validation is part of the M11.4 gate**.

Implemented capabilities include bounded route-trace/upstream evidence, read-only SNMP, IF/IP/BRIDGE/Q-BRIDGE/LLDP evidence, router interfaces and connected prefixes, ARP/ND, conservative FDB/switch-port/VLAN projection, historical topology comparison, and fail-visible `partial/source_errors` behavior.

WireScope never invents an invisible L2 switch. Physical relationships require direct evidence.

### M11.4 — topology hardening and evidence sufficiency

Status: **implementation complete; automated regression, Chromium, wheel build, and installed-wheel smoke are green; live VM validation remains**.

Implemented:

- `coverage` / claimability domains for inventory, L3, L2, traffic, VLAN, Wi-Fi, and hypervisor evidence using `sufficient / partial / missing`;
- structural presentation separated from the full canonical evidence graph;
- infrastructure-first rendering that prevents directed broadcast, link-local noise, and PCAP-only external endpoints from masquerading as ordinary infrastructure in the structural view;
- full-diagram export separated from current-viewport export;
- persisted per-interface default routes and DHCP router-option evidence for multi-homed WireScope hosts;
- interface gateway projection only from exact persisted evidence, never `.1/.254/.11` guessing;
- optional read-only SSH topology enrichment for Linux/OpenWrt-like managed devices;
- strict SSH host-key verification, fixed `ip/bridge/iw` command allowlist, no arbitrary remote command, and no shell execution;
- consume-once `0600` credential spool for SSH private key/known_hosts material;
- immediate cleanup of queued SNMP/SSH credentials on cancel and fresh-credentials requirement for retry;
- conservative SSH FDB/VLAN semantics: exact FDB VLAN or an unambiguous single-VLAN access port may establish endpoint VLAN; trunk/hybrid ports never force an arbitrary VLAN;
- Wi-Fi association evidence from read-only management data when available;
- source-health coverage for route-trace, SNMP, and SSH so omitted job-backed persisted evidence becomes visible as `partial/source_errors`;
- dedicated regression for SSH role/scope/credential lifecycle, source health, and access-vs-trunk VLAN projection.

See [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md) for the evidence and claimability contract.

### v1.2 live-validation gate

The previous M11 checkpoint has already been upgraded successfully on an installed WireScope VM with healthy API/worker, migrations, capabilities, and dumpcap privilege path.

M11.4 requires a **new Deep audit**, because older retained audits do not contain the new per-interface default-route/DHCP lease evidence.

Live validation must cover:

- upgrade to the M11.4 checkpoint while preserving retained audits;
- a new Deep audit on the selected interface and confirmed scope;
- structural-map readability and suppression/grouping of non-structural broadcast/link-local/PCAP-only noise;
- truthful `coverage` states and recommendations;
- interface-specific gateway projection on a multi-homed appliance;
- L2/L3/Traffic/All-evidence views and explicit PCAP overlay;
- findings/details, zoom/pan/fit, JSON/SVG/PNG exports, and topology history diff;
- read-only SNMP on an available router/switch, or read-only SSH on a suitable Linux/OpenWrt device, to validate real interface/route/neighbour/FDB/VLAN/LLDP/Wi-Fi evidence where supported;
- absence of false router/VLAN/L2 classification and fail-visible source errors.

After a green live check, v1.2 receives the final topology checkpoint and development moves to v1.3.

## v1.3 — Global Correlation Analysis

Goal: combine active/deep audit results, selected PCAP Traffic Analysis, findings, and Network Topology into a deterministic `global-analysis` package.

The first implementation should correlate exact identities and persisted evidence only: observed service use, finding relevance to observed traffic, inventory-only assets, external endpoints related to internal assets, and topology/gateway/DHCP/DNS consistency. Missing relationships remain `uncorrelated`, not guessed.

Global Analysis must work **without external AI**.

## v1.4 — AI-assisted Global Analysis

Optional AI analysis may be added only on top of deterministic global correlations. Raw PCAP is not sent by default; provider data transfer is a separate trust boundary and requires explicit operator control. AI output is an analytical conclusion/hypothesis, not an automatic WireScope finding.

## Current next step

**M11.4 live-network validation:** upgrade the WireScope VM to the hardening checkpoint, run a new Deep audit, verify structural topology + `coverage` + interface-specific gateway, then validate read-only SNMP or SSH management evidence where a suitable managed device is available. Fix only confirmed live interoperability/UX defects. After a green live check, close v1.2 and start v1.3 Global Correlation Analysis.
