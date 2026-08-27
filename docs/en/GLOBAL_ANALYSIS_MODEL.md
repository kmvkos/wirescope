# Global Correlation Analysis model

[Русский](../GLOBAL_ANALYSIS_MODEL.md)

Global Analysis combines already-persisted WireScope results into one reproducible analytical document. It does not launch scanners, re-read PCAP, or perform new network I/O.

```text
persisted inventory/findings
          +
explicit traffic-analysis result
          +
canonical network-topology
          ↓
     global-analysis v1
```

## Core rules

- inventory/traffic identity uses exact IP or exact MAC only;
- hostname alone never merges identities;
- an inventory asset missing from the selected PCAP is not considered absent from the network;
- a private endpoint outside known topology segments is not automatically labelled external/Internet;
- partial/missing input state is inherited by the result;
- correlation confidence cannot exceed the underlying evidence;
- evidence lineage contains ID/hash/type/schema metadata but no filesystem path;
- preview, durable execution, and rebuild use the same canonical correlation contract;
- rebuild creates a new immutable job/artifact and never rewrites an older result.

## API

### Offline preview

```text
GET /api/v1/audits/{audit_id}/global-analysis?traffic_analysis_job_id={job_id}
```

Preview uses current persisted sources without creating a new artifact.

### Durable stage

```text
POST /api/v1/audits/{audit_id}/global-analysis
{
  "traffic_analysis_job_id": "...",
  "priority": 0
}
```

The worker persists the canonical result as:

```text
artifact_type  = global_analysis_result
schema         = global-analysis
schema_version = 1
retention      = audit
```

### History and result access

```text
GET /api/v1/audits/{audit_id}/global-analysis/history
GET /api/v1/jobs/{job_id}/global-analysis
GET /api/v1/jobs/{job_id}/global-analysis/export?format=json
GET /api/v1/jobs/{job_id}/global-analysis/export?format=text
GET /api/v1/jobs/{job_id}/global-analysis/export?format=markdown
```

History includes durable jobs for the selected audit, including queued/running/failed/cancelled/interrupted states. A canonical result is readable only for a completed job with a valid registered `global_analysis_result` artifact.

### Rebuild

```text
POST /api/v1/audits/{audit_id}/global-analysis
{
  "traffic_analysis_job_id": "...",
  "rebuild_of_job_id": "previous-global-analysis-job-id"
}
```

Rebuild creates a new job. The previous artifact remains unchanged. `rebuild_of_job_id` must reference Global Analysis from the same audit, and the selected Traffic Analysis must match the previous result. Rebuild is not stage resume and not an in-place update.

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

Each correlation row has a deterministic ID and a versioned `rule_id`. Durable `execution` adds job/rebuild lineage without changing identity or correlation semantics.

## Asset ↔ traffic identity

Rule:

```text
GA-ASSET-IDENTITY-001
```

Match order:

1. exact canonical IP;
2. exact canonical MAC;
3. otherwise `unmatched`.

Hostname, vendor, similar MAC prefixes, and device class are not identity keys.

If multiple assets unexpectedly claim the same exact identifier, WireScope returns `identity_conflict`, marks the analysis `partial`, and does not merge them automatically.

## Traffic endpoint classification

An endpoint receives one conservative class:

- `internal_asset` — exact match to an inventory asset;
- `internal_segment` — IP belongs to a known topology segment but no asset was matched;
- `external_global` — globally routable IP outside known internal segments;
- `private_unknown` — private IP outside known segments;
- `special` — multicast/link-local/unspecified/broadcast;
- `unknown` — insufficient evidence.

`private_unknown` is deliberately not called external: missing inventory/topology evidence does not prove an organizational or Internet boundary.

## Service ↔ observed traffic

Rule:

```text
GA-SERVICE-USAGE-001
```

The current contract uses the pair-level `communications_graph` from `traffic-analysis` v1.

If an endpoint exact-matches an asset, inventory contains `(protocol, port)` for that asset, and the same `protocol/port` appears among the pair's aggregated destination ports, the service gets `observed_in_selected_traffic=true`.

### Direction limitation

The communications graph aggregates destination ports per endpoint pair and does not retain which endpoint owned the matching port. The match basis is therefore:

```text
observed_pair_destination_port
```

with `observed`, not `confirmed`, confidence.

It means the service port was observed within a communication pair containing the asset; it does not yet prove a directional client → specific server socket relationship. Stronger directional service-use correlation requires a later traffic-analysis contract extension.

## Finding ↔ traffic relevance

Rule:

```text
GA-FINDING-TRAFFIC-RELEVANCE-001
```

States:

- `service_traffic_observed` — finding references a service whose port was observed in the selected PCAP;
- `asset_traffic_observed` — no service-level match, but the asset exact-matches a traffic endpoint;
- `uncorrelated` — the selected PCAP provides no such link.

`uncorrelated` does **not** mean the finding is unimportant or false. It only describes visibility from the selected capture.

## Inventory ↔ Traffic coverage

Rule:

```text
GA-INVENTORY-TRAFFIC-COVERAGE-001
```

WireScope separately reports inventory assets correlated with traffic, inventory assets not visible in the selected capture, and traffic endpoints not matched to inventory.

This is a visibility comparison, not a percentage estimate of the real network.

## Internal ↔ external communications

Rule:

```text
GA-EXTERNAL-COMMUNICATION-001
```

An external communication is created only when one side exact-matches an inventory asset and the other side is classified `external_global`.

The row preserves internal asset ID, external endpoint, packets/bytes, persisted protocols/ports, and the deterministic conversation ID. Private unknown communications remain separate in `unclassified_communications`.

## Infrastructure consistency

Rules:

```text
GA-GATEWAY-CONSISTENCY-001
GA-DHCP-CONSISTENCY-001
GA-DNS-CONSISTENCY-001
```

Global Analysis compares independent persisted observations:

- gateway: interface-specific environment/default route + passive DHCP router + canonical topology;
- DHCP server: local DHCP lease + passive DHCP + selected Traffic Analysis;
- DNS server: interface DHCP/environment DNS + selected Traffic Analysis + topology role evidence.

States:

- `consistent` — at least two available sources share a common value;
- `divergent` — at least two sources exist but share no value;
- `insufficient` — fewer than two independent sources are available.

Divergence does not make the document `partial`; it is a correlation result. `partial` is reserved for incomplete or damaged source evidence.

## Evidence lineage

`evidence_references` links the result to the audit, selected traffic-analysis job/artifact, inventory asset/service IDs, finding IDs, and route/SNMP/SSH topology artifacts.

Artifact references contain safe metadata only: ID, type, content type, size, SHA-256, schema/version, and timestamp. Internal relative or absolute filesystem paths are excluded from the canonical document.

Correlation rows also carry compact `evidence_refs`.

## Operator summary and exports

`operator_summary` is a deterministic Russian-language operational summary over canonical data. TXT and Markdown exports are rendered from the same persisted JSON and do not run the analysis again.

The summary covers matched inventory assets, observed service ports, finding ↔ traffic relevance, external communications, gateway/DHCP/DNS consistency, and partial/source-health limitations.

## Operator GUI

The WireScope home screen exposes **Global Analysis**. The workspace lets the operator:

- select a retained audit;
- explicitly select a completed Traffic Analysis;
- start a durable Global Analysis job (auditor);
- observe queued/running progress and cancel the job;
- browse historical results (auditor/viewer);
- open an older immutable result;
- rebuild with the same Traffic Analysis while retaining `rebuild_of_job_id` lineage;
- export JSON/TXT/Markdown;
- inspect summary, infrastructure consistency, coverage/source health, finding relevance, external communications, warnings, and evidence lineage.

The GUI does not modify active scope and does not initiate network I/O.

## Source health and partial state

Examples:

- truncated report/inventory source → `inventory=partial`;
- topology `partial=true` → `topology=partial`;
- missing communications graph → `traffic=missing`;
- identity conflict → `identity=partial`.

Overall `partial=true` means the document remains useful, but some claims are constrained by source quality.

## Remaining work before v1.3 closure

- automated regression and installed-wheel smoke for history/rebuild/UI contracts;
- live install/upgrade on a WireScope VM;
- a real durable Global Analysis run over an existing Deep audit and retained Traffic Analysis;
- operator validation of GUI, history, rebuild, and exports on the installed appliance;
- an optional directional traffic projection for stronger service-use claims if needed; this is an enhancement, not a safety requirement for the current contract.

v1.3 does not use AI and does not automatically create findings from correlation output. AI-assisted analysis remains a separate v1.4 layer.
