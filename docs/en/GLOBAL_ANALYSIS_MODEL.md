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
- the result is offline and deterministic.

## API

```text
GET /api/v1/audits/{audit_id}/global-analysis?traffic_analysis_job_id={job_id}
```

`audit_id` selects the inventory/findings/topology audit. `traffic_analysis_job_id` is explicitly selected by the operator and must reference a completed `traffic_analysis` job with a registered `traffic_analysis_result` artifact.

## Canonical contract

The first contract contains:

```text
global-analysis v1
├── inputs
├── summary
├── asset_traffic_identity
├── service_usage
├── finding_traffic_relevance
├── external_communications
├── unclassified_communications
├── coverage
├── source_health
├── partial
└── warnings
```

Each correlation row has a deterministic ID and a versioned `rule_id`.

## Asset ↔ traffic identity

Current rule:

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

The first slice uses the pair-level `communications_graph` from `traffic-analysis` v1.

If an endpoint exact-matches an asset, inventory contains `(protocol, port)` for that asset, and the same `protocol/port` appears among the pair's aggregated destination ports, the service gets `observed_in_selected_traffic=true`.

### Direction limitation

The current communications graph aggregates destination ports per endpoint pair and does not retain which endpoint owned the matching port. The match basis is therefore:

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

The row preserves internal asset ID, external endpoint, packets/bytes, persisted protocols/ports, and the deterministic conversation ID. Private unknown communications are kept separately in `unclassified_communications`.

## Source health and partial state

Global Analysis inherits source quality. A truncated report source produces `inventory=partial`; topology `partial=true` produces `topology=partial`; a missing communications graph produces `traffic=missing`; identity conflicts produce `identity=partial`.

Overall `partial=true` means the document remains useful, but some correlations are constrained by source quality.

## First-slice limits

The first slice does not persist a dedicated `global_analysis_result` artifact, has no separate job lifecycle, does not re-read PCAP for directional service mapping, does not use hostname-only identity, does not use AI, and does not create new findings automatically.

A later slice can add durable artifact/job semantics on top of the stable `global-analysis v1` contract without changing the safety model.
