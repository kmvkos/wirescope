# WireScope — Post-1.0 Roadmap

[Русский](../ROADMAP.md)

This roadmap describes development after the v1.0 feature freeze.

WireScope remains a **portable self-contained network auditor** rather than quietly expanding into a SIEM/NDR/SOC platform. New work must preserve the safety contracts: passive observation is not active authorization, scope is operator-confirmed, external tools run without a shell, and conclusions remain traceable to persisted evidence.

## v1.0 — Base network auditor

Status: **feature complete / frozen**.

The baseline includes passive analysis, standalone PCAP capture, operator-confirmed active scope, Discovery/Standard/Deep profiles, inventory, protocol audits, findings/evidence, HTML/JSON/Markdown reports, audit diff, diagnostics, retention/recovery, web/kiosk UI, and appliance backup/restore.

After freeze, the line accepts bug fixes, compatibility work, and release engineering rather than hidden scope expansion.

---

## v1.1 — PCAP Traffic Analysis

Status: **implementation complete; core live scenarios passed**.

Retained PCAP is analyzed offline without a new capture or network I/O.

Implemented capabilities include duration/frames/bytes/rates, top talkers and communications graph, TCP health, DNS latency/errors, ARP/DHCP/ICMP diagnostics, broadcast/multicast contributors, TLS/HTTP/QUIC/SMB metadata without payload decryption, ACK RTT summaries, persisted-result comparison, canonical `traffic-analysis` JSON, text/Markdown exports, and web/kiosk UI.

Traffic Analysis is the **source-of-truth for what was observed during a specific capture window**. It must not become a second Audit Report.

---

## v1.2 — Network Topology

Status: **feature complete / closed**.

M11.1–M11.4 are implemented and the main topology path was live-validated on the WireScope VM.

Topology combines persisted inventory/ARP/ND/routes/DHCP/LLDP/CDP/STP/VLAN/active evidence plus an explicitly selected Traffic Analysis. Structural/L2/L3/Traffic/All Evidence views, subnet regions, historical compare, JSON/SVG/PNG exports, VLAN focus, and optional read-only SNMP/SSH enrichment are implemented.

`coverage` / claimability reports `sufficient / partial / missing` for evidence domains. WireScope does not guess gateways, physical links, VLANs, or Wi-Fi attachment when evidence is insufficient. Management-learned topology does not expand active scope.

See [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md).

---

## v1.3 — Correlated Assessment

Status: **feature complete / closed**.

The product-facing name is **Correlated Assessment** / Russian **«Корреляция результатов»**. Technical identifiers `global_analysis`, `global-analysis`, and `/global-analysis` remain for backward compatibility.

The purpose is not to claim “deep global analysis”. It shows **what already-persisted sources confirm or add to each other**.

Implemented:

- exact IP/MAC inventory ↔ traffic identity without hostname-only merge;
- service ↔ observed traffic correlation;
- finding ↔ observed asset/service relevance without changing source severity;
- inventory ↔ selected-capture visibility;
- exact-correlated internal asset ↔ globally routable endpoint;
- conservative `private_unknown` classification;
- gateway/DHCP/DNS cross-source consistency;
- inherited partial/source-health state;
- deterministic IDs/rule IDs and safe evidence lineage;
- offline preview;
- durable `global_analysis` job + `global_analysis_result` artifact;
- immutable history/rebuild;
- JSON/TXT/Markdown exports;
- operator GUI;
- automated compile/pytest/JS-syntax/wheel/installed-wheel validation;
- live validation on the installed WireScope VM.

### Hard boundary

Correlated Assessment **must not duplicate source reports**. A source fact appears only when required to explain a relationship between sources.

v1.3 intentionally does not include behavioral/anomaly baselines, attack/intent inference, threat-intelligence/reputation scoring, a large traffic pattern engine, automatic new security findings from correlation output, AI analysis, or an attempt to replace SIEM/NDR tooling.

`traffic-analysis` v1 aggregates destination ports per communication pair, so service-use correlation remains pair-level `observed_pair_destination_port`. A more precise directional flow contract may be added later as a separate Traffic Analysis improvement; it is not unfinished v1.3 work.

See [GLOBAL_ANALYSIS_MODEL.md](GLOBAL_ANALYSIS_MODEL.md).

---

## Next stage — Product Coherence Review

This is **not a new major feature**. It is a systematic review of the existing product before further expansion.

The goal is to remove repeated information across Audit Report, Traffic Analysis, Network Topology, Correlated Assessment, dashboard/operator views, and HTML/JSON/Markdown/TXT exports.

Ownership rules:

1. **Audit Report** owns inventory, discovered services, protocol-audit findings, rationale/recommendations, and audit evidence.
2. **Traffic Analysis** owns facts from a specific capture window: traffic metrics, conversations, protocol observations, and network diagnostics.
3. **Network Topology** owns structure, relationships, and claimability; it does not restate security or traffic reports in full.
4. **Correlated Assessment** owns cross-source relationships only and references source data instead of repeating it.
5. Dashboard/UI summaries provide compact navigation and status rather than another full report.

The outcome must be enforced in code and in reporting/GUI documentation and regression tests.

---

## Ideas after the coherence review

These are not current commitments and require separate design:

- external PCAP import and safe integration with the existing Traffic Analysis pipeline;
- PDF export;
- additional protocol-audit modules;
- controlled/local CVE enrichment;
- scheduled audits;
- long-term traffic baselines;
- cross-site topology history;
- hypervisor-specific topology providers;
- vendor-specific management-plane adapters;
- broader distro/architecture/tshark compatibility coverage.

External PCAP import is intentionally not specified yet; its UX, ownership, limits, and trust model will be designed separately.

## Current next step

**Run the Product Coherence Review and remove duplicated report/view content.**
