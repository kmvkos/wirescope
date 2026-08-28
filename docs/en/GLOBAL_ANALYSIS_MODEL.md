# Correlated Assessment — v1.3

[Русский](../GLOBAL_ANALYSIS_MODEL.md)

The user-facing feature is called **Correlated Assessment**. Historical technical identifiers remain `global_analysis`, `global-analysis`, and `/global-analysis` for compatibility with existing jobs, artifacts, and API clients.

## Purpose

Correlated Assessment answers two practical questions:

> What becomes visible when already-persisted audit results, PCAP Traffic Analysis, and Network Topology are compared with each other?

> When the persisted evidence is not sufficient for a stronger conclusion, exactly what is missing and how can the operator collect it?

It is **not** a SIEM, NDR, UEBA, anomaly detector, or a claim of deep global behavioral analysis. WireScope does not infer host intent, build long-term behavioral baselines, or attempt to replace a SOC platform.

```text
persisted audit / inventory / findings
                 +
explicitly selected Traffic Analysis
                 +
canonical Network Topology
                 ↓
        Correlated Assessment
   technical schema: global-analysis v1
                 ↓
      relationships + evidence gaps
```

Correlation remains fully offline: it does not start a scanner, re-read a PCAP, or perform new network I/O. Collection options are operator guidance only; they are never executed automatically.

## Presentation contract

Correlated Assessment **must not duplicate source reports**.

A fact from Audit Report, Traffic Analysis, or Topology is shown only when required to explain a cross-source relationship or explain why a particular conclusion cannot yet be confirmed. Full detail remains owned by the original source-of-truth.

Valid examples include:

- a service discovered by the audit whose port was observed in the selected PCAP;
- a finding attached to an asset/service visible in traffic;
- an inventory asset not observed in the selected capture window;
- a traffic endpoint that cannot be exact-matched to inventory;
- an exact-correlated internal asset communicating with a globally routable endpoint;
- independent gateway/DHCP/DNS observations that agree or diverge;
- one source reporting a gateway while no second independent source confirms it, together with explicit guidance for collecting confirmation.

Correlation must not reproduce full inventory, full service lists, full finding rationale/remediation, or the complete Traffic Analysis report.

## Correlation domains

### Asset ↔ traffic identity

Rule: `GA-ASSET-IDENTITY-001`.

Identity uses only exact canonical IP or exact canonical MAC. Hostname, vendor, device class, or similar MAC prefixes are not identity keys. Ambiguous exact identifiers produce `identity_conflict`, set the document `partial`, and are never auto-merged.

### Service ↔ observed traffic

Rule: `GA-SERVICE-USAGE-001`.

If a communication endpoint exact-matches an inventory asset and the discovered `(protocol, port)` occurs in the persisted `communications_graph`, the service receives `observed_in_selected_traffic=true`.

`traffic-analysis` v1 aggregates destination ports per communication pair, so the match basis remains `observed_pair_destination_port`. This confirms that the service port appeared in a pair containing the asset, but does not prove a directional client → specific server socket relationship.

The evidence-gap layer therefore states that a bidirectional flow/handshake or another suitable directional source is required before server direction can be claimed strictly.

### Finding ↔ observed traffic

Rule: `GA-FINDING-TRAFFIC-RELEVANCE-001`.

States are `service_traffic_observed`, `asset_traffic_observed`, and `uncorrelated`.

`uncorrelated` means only that the selected PCAP did not provide that relationship. It does not change finding severity and does not mean the finding is false or unimportant. When traffic corroboration is missing, a gap may recommend a more suitable capture window/segment or resolving endpoint identity first.

### Inventory ↔ Traffic visibility

Rule: `GA-INVENTORY-TRAFFIC-COVERAGE-001`.

The result distinguishes inventory assets exact-correlated with traffic, inventory assets not observed in the selected capture, and traffic endpoints without exact inventory identity. This is a visibility comparison, not an estimate of how much of the real network is known.

### Internal ↔ global endpoints

Rule: `GA-EXTERNAL-COMMUNICATION-001`.

A row is produced only when one side exact-matches an inventory asset and the other is classified `external_global`. A private address outside known topology segments remains `private_unknown` instead of being automatically labelled Internet/external.

### Infrastructure consistency

Rules:

```text
GA-GATEWAY-CONSISTENCY-001
GA-DHCP-CONSISTENCY-001
GA-DNS-CONSISTENCY-001
```

Independent persisted observations from environment/passive/Traffic Analysis/topology are compared. `consistent` means at least two sources share a value, `divergent` means at least two are available but share no value, and `insufficient` means there are not enough independent sources.

### Evidence gaps — what is missing for confirmation

Rule family: `GA-EVIDENCE-GAP-001`.

`evidence_gaps` are **not findings and not warnings**. A gap is created when some starting evidence already exists, or sources conflict, but the evidence is insufficient for a stronger cross-source conclusion.

If an infrastructure check has no starting fact from any source, no evidence-gap card is created. That condition remains part of `source_health`/coverage instead of producing a noisy list of “we know nothing” cards.

Every gap contains:

```text
id
rule_id
category
status                  needs_evidence | conflicting_evidence
priority                high | medium | low
title
known_evidence          what is already known
missing_evidence        what is missing and why
collection_options      concrete collection options
safe_conclusion         strongest supported claim right now
affected                aggregated affected objects
evidence_refs           references to persisted evidence
related_rule_ids
```

Gaps are deliberately aggregated: WireScope does not create hundreds of identical cards when several hosts share the same evidence deficiency.

Typical categories include:

- insufficient/conflicting gateway, DHCP, or DNS evidence;
- ambiguous IP/MAC identity;
- internal/private PCAP endpoints not matched to inventory;
- service ports observed at communication-pair level without directional server proof;
- services discovered by audit but not observed in the selected PCAP;
- findings without additional traffic corroboration;
- audited assets not visible in the selected capture window;
- partial topology;
- missing usable Traffic Analysis communications graph.

`collection_options` may recommend a longer or better-positioned PCAP, DHCP/ARP observation, SPAN/mirroring for a relevant VLAN, active discovery **only inside already-confirmed scope**, or SNMP/SSH topology enrichment. These suggestions never expand authorization and never initiate collection by themselves.

`safe_conclusion` is mandatory: until stronger evidence exists, WireScope explicitly states the strongest claim supported by the current persisted sources and does not take the next logical step without proof.

### Evidence quality

Partial/missing source state is inherited. Correlation confidence never exceeds source evidence confidence. `evidence_references` contains safe ID/type/hash/schema/timestamp references, never filesystem paths.

## Canonical contract

```text
global-analysis v1
├── inputs
├── execution
├── summary
├── asset_traffic_identity
├── service_usage
├── finding_traffic_relevance
├── external_communications
├── unclassified_communications
├── infrastructure_consistency
├── evidence_gaps
├── coverage
├── source_health
├── evidence_references
├── operator_summary
├── partial
└── warnings
```

Adding `evidence_gaps` is an additive evolution of `global-analysis v1`; historical identifiers and API paths remain unchanged.

## Durable execution and API

Preview:

```text
GET /api/v1/audits/{audit_id}/global-analysis?traffic_analysis_job_id={job_id}
```

Durable run:

```text
POST /api/v1/audits/{audit_id}/global-analysis
{
  "traffic_analysis_job_id": "...",
  "priority": 0
}
```

Persisted result:

```text
job_type       = global_analysis
artifact_type  = global_analysis_result
schema         = global-analysis
schema_version = 1
retention      = audit
```

History/read/export:

```text
GET /api/v1/audits/{audit_id}/global-analysis/history
GET /api/v1/jobs/{job_id}/global-analysis
GET /api/v1/jobs/{job_id}/global-analysis/export?format=json
GET /api/v1/jobs/{job_id}/global-analysis/export?format=text
GET /api/v1/jobs/{job_id}/global-analysis/export?format=markdown
```

Rebuild creates a new immutable job/artifact with `rebuild_of_job_id`; the previous result is never rewritten and the selected Traffic Analysis source must remain the same.

## Operator GUI

The main human-facing block after the short operator summary is **“What still needs confirmation”** (Russian UI: **«Что ещё нужно подтвердить»**). Each evidence-gap card shows:

1. what is already known;
2. what is missing;
3. how the operator can collect it;
4. what can safely be claimed right now.

Lower-level relationship sections follow afterward: infrastructure consistency, coverage/source health, findings ↔ traffic, external communications, and evidence lineage.

TXT/Markdown exports use the same structure; JSON retains the deterministic machine contract.

## Non-goals

Correlated Assessment intentionally does **not** include:

- behavioral/anomaly baselines;
- attack/intent inference;
- threat-intelligence or reputation scoring;
- a large traffic-behavior pattern library;
- automatic source-finding severity changes;
- automatic new security findings from correlation output;
- AI analysis;
- automatic execution of suggested evidence collection;
- repetition of Audit/Traffic/Topology reports.

Evidence gaps do not widen that boundary: they explain evidence insufficiency and present safe operator collection options.

## Status

The core v1.3 Correlated Assessment is closed. v1.3.3 is a bounded additive operator-guidance improvement: deterministic evidence gaps without expanding WireScope network activity, authorization, or analytical scope.
