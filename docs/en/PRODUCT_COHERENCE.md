# Product Coherence — WireScope reports and views

[Русский](../PRODUCT_COHERENCE.md)

Status: **review complete / closed**.

This document defines **which subsystem owns which information** and how WireScope avoids repeating the same data across reports and operator views.

## Core rule

Each information class has one source-of-truth.

Another view/export may show brief context only when that fact is required for its own task. Full tables, rationale, recommendations, and detailed diagnostics stay with the owner.

```text
owner → full detail
summary/context → compact representation
cross-source view → relationship + reference to owner
```

## Ownership matrix

| Subsystem | Owns | Must not do |
|---|---|---|
| Audit Report | inventory, discovered services, protocol-audit results, findings, severity/confidence, rationale, recommendations, audit evidence | reproduce a full PCAP diagnostic report |
| Traffic Analysis | facts from one capture window, rates, conversations, protocol visibility, TCP/DNS/ARP/DHCP/ICMP diagnostics, observed metadata | turn protocol presence into a security finding or duplicate Audit Report remediation |
| Network Topology | nodes/edges, L2/L3/Traffic relationships, VLAN, infrastructure roles, claimability/coverage | reproduce full findings/traffic reports |
| Correlated Assessment | cross-source audit↔traffic↔topology relationships | copy source reports or become another vulnerability report |
| Dashboard/operator summary | status, compact counts, navigation to the owner | become another full report |

## Audit Report

Audit Report is the owner when the question is:

- which assets and services were discovered;
- which protocol audits ran;
- which security findings were created;
- why a finding matters;
- what should be checked/remediated;
- which audit evidence supports the conclusion.

Security severity, rationale, and remediation belong to Findings/Audit Report.

## Traffic Analysis

Traffic Analysis answers:

> What was visible in this specific PCAP, and which network diagnostic signals were present?

It may show protocol presence, TCP health, DNS errors/latency, ARP conflicts, DHCP observations, broadcast/multicast, protocol metadata, communications, top talkers, and rates.

Mere Telnet/FTP/HTTP presence must not become a Traffic Analysis security finding with independent severity and remediation. If an Audit Report exists, security assessment belongs there; Correlated Assessment may link the traffic observation to the discovered service/finding.

### Internal Traffic Analysis deduplication

Human-readable Traffic Analysis is split into:

1. capture summary / traffic character;
2. network diagnostics;
3. protocol detail;
4. limitations.

A detailed list has one presentation owner. DNS top names belong to Protocol Detail and are not repeated in DNS Diagnostics. DHCP server identifiers belong to Protocol Detail and are not repeated in generic ARP/ICMP diagnostics.

## Network Topology

Topology may show finding/traffic badges as node or edge context, but it does not duplicate complete rationale/remediation or full communication reports. Structural view remains infrastructure-first.

SNMP/SSH management sources are explicit optional/lazy sources. Their UI/renderers must not alter normal topology behavior after the operator leaves the advanced management view.

## Correlated Assessment

Correlated Assessment shows only information created **by the relationship between sources**: service observed in traffic, finding attached to a traffic-visible asset/service, inventory-vs-capture visibility, unmatched traffic endpoints, infrastructure consistency, and exact-correlated internal↔global communication.

It may include minimal source context, but not full source sections.

## Dashboard and GUI

Dashboard answers “where should the operator look next?”. Compact counters/status/navigation are valid. Embedding another complete Audit Report or Traffic Analysis is not.

## Export policy

HTML/Markdown/TXT/JSON for a product must follow the same ownership model as the GUI. JSON may contain canonical machine-readable owner data; human-readable exports are deduplicated and task-oriented.

## Compatibility

Coherence changes should prefer presentation/interpretation layers without deleting canonical persisted evidence.

When persisted Traffic Analysis semantics materially change, increment `ANALYZER_VERSION` so an older retained PCAP can be re-analyzed instead of silently reusing an older semantic result.

## Acceptance criteria

The review is complete when protocol presence is no longer presented as a Traffic security finding, security rationale/remediation has one owner, repeated DNS/DHCP detail is removed from the current Traffic renderer, Correlated Assessment remains cross-source only, topology remains relationship/claimability focused, docs agree on ownership, regression tests lock these anti-duplication contracts, and optional SNMP/SSH topology modules do not keep issuing management reads after the operator returns to the normal topology view.

**All criteria above are satisfied.** The final code checkpoint passed the complete automated gate: compile, JS syntax, pytest, Chromium kiosk/web smoke, wheel build, and installed-wheel smoke.
