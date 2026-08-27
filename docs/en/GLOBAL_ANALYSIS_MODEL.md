# Correlated Assessment — v1.3

[Русский](../GLOBAL_ANALYSIS_MODEL.md)

The user-facing feature is called **Correlated Assessment**. Historical technical identifiers remain `global_analysis`, `global-analysis`, and `/global-analysis` for compatibility with existing jobs, artifacts, and API clients.

## Purpose

Correlated Assessment answers one practical question:

> What becomes visible when already-persisted audit results, PCAP Traffic Analysis, and Network Topology are compared with each other?

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
```

Correlation is fully offline: it does not start a scanner, re-read PCAP, or perform new network I/O.

## Presentation contract

Correlated Assessment **must not duplicate source reports**.

A fact from Audit Report or Traffic Analysis is shown only when it is required to explain a relationship between sources. Full detail remains owned by the original source-of-truth.

Valid examples include:

- a service discovered by the audit whose port was observed in the selected PCAP;
- a finding attached to an asset/service visible in traffic;
- an inventory asset not observed in the selected capture window;
- a traffic endpoint that cannot be exact-matched to inventory;
- an exact-correlated internal asset communicating with a globally routable endpoint;
- independent gateway/DHCP/DNS observations that agree or diverge.

Correlation must not reproduce full inventory, full service lists, full finding rationale/remediation, or the complete Traffic Analysis report.

## Correlation domains

### Asset ↔ traffic identity

Rule: `GA-ASSET-IDENTITY-001`.

Identity uses only exact canonical IP or exact canonical MAC. Hostname, vendor, device class, or similar MAC prefixes are not identity keys. Ambiguous exact identifiers produce `identity_conflict`, set the document `partial`, and are never auto-merged.

### Service ↔ observed traffic

Rule: `GA-SERVICE-USAGE-001`.

If a communication endpoint exact-matches an inventory asset and the discovered `(protocol, port)` occurs in the persisted `communications_graph`, the service receives `observed_in_selected_traffic=true`.

`traffic-analysis` v1 aggregates destination ports per communication pair, so the match basis remains `observed_pair_destination_port`. This confirms that the service port appeared in a pair containing the asset, but does not prove a directional client → specific server socket relationship.

A directional flow projection may be added later as a Traffic Analysis improvement; it is not required for v1.3 closure.

### Finding ↔ observed traffic

Rule: `GA-FINDING-TRAFFIC-RELEVANCE-001`.

States are `service_traffic_observed`, `asset_traffic_observed`, and `uncorrelated`.

`uncorrelated` means only that the selected PCAP did not provide that relationship. It does not change finding severity and does not mean the finding is false or unimportant.

### Inventory ↔ Traffic visibility

Rule: `GA-INVENTORY-TRAFFIC-COVERAGE-001`.

The result distinguishes inventory assets exact-correlated with traffic, inventory assets not observed in the selected capture, and traffic endpoints without exact inventory identity. This is a visibility comparison, not a percentage estimate of the real network.

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
├── coverage
├── source_health
├── evidence_references
├── operator_summary
├── partial
└── warnings
```

The technical schema name remains unchanged for backward compatibility. The product-facing term is **Correlated Assessment**.

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

The home-screen action is **Correlated Assessment** / Russian **«Корреляция результатов»**.

The workspace selects an audit and one completed Traffic Analysis, runs durable correlation, exposes progress/history, opens immutable previous results, supports rebuild, and exports JSON/TXT/Markdown.

Presentation is intentionally relationship-focused: correlation summary, cross-source additions, infrastructure consistency, coverage/source health, finding ↔ observed traffic, internal assets ↔ global endpoints, interpretation limits, and evidence lineage.

## Non-goals

v1.3 intentionally does **not** include:

- behavioral/anomaly baselines;
- attack/intent inference;
- threat-intelligence or reputation scoring;
- a large traffic-behavior pattern library;
- automatic source-finding severity changes;
- automatic new security findings from correlation output;
- AI analysis;
- repetition of Audit/Traffic/Topology reports.

Any future capability in those classes must be an explicitly scoped feature rather than a hidden expansion of Correlated Assessment.

## v1.3 status

**Feature complete / closed.**

Deterministic correlation, durable storage, evidence lineage, consistency checks, history/rebuild/exports, and the operator GUI are implemented. Automated compile/pytest/JS syntax/wheel/installed-wheel gates passed, and the feature was validated on the installed WireScope VM.

The next product step is not deeper correlation. It is a **product-wide review of WireScope views and reports for duplicated information and clear source-of-truth ownership**.
