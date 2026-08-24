# WireScope reporting

[Русский](../REPORTING_MODEL.md) · **English**

A WireScope report is built from data that has already been persisted by the audit. Report generation does not re-run Nmap, protocol modules, or passive capture.

That distinction matters: a report should be a reproducible view of audit state, not another hidden scanning stage.

## Data flow

```text
audit metadata
+ environment snapshot
+ confirmed scope
+ passive result / assessment
+ inventory
+ protocol observations
+ findings
+ artifact metadata
        ↓
report view model
schema: audit-report v1
        ↓
HTML + JSON
        ↓
EvidenceStore + reports history
```

Published JSON Schema:

```text
reports/schema/audit-report-v1.json
```

## Report contents

### Executive summary

The summary includes the main counts and a compact narrative:

- asset/service/finding counts;
- passive capture frame count;
- whether the capture NIC had an L3 address;
- 802.1Q VLAN IDs actually seen in frames;
- segment note;
- highest open severity;
- headline/summary.

The current Russian narrative is deterministic. It is produced from persisted data and does not use an LLM to invent prose or CVEs.

### Environment

- hostname;
- capture interface;
- L3 presence;
- discovered interfaces;
- default route;
- DNS.

### Passive assessment

- duration and frame count;
- observed 802.1Q tags;
- LLDP/CDP neighbors;
- STP;
- ARP;
- DHCP;
- mDNS/LLMNR/NBNS summaries;
- assessment conclusions and confidence.

### Scope

The audit scope and the confirmed active-scan snapshot are both represented.

### Inventory

Persisted assets and services.

### Findings

The report includes open findings as well as `suppressed` and `accepted_risk` findings so that operator decisions are not lost.

Recommendations are derived from open findings.

### Evidence references

The primary report does not embed raw PCAP/XML/stdout.

Evidence is referenced by metadata:

- artifact id;
- type;
- content type;
- size;
- SHA-256.

Internal filesystem `relative_path` values are not exported in the public JSON model.

## Generation

```text
POST /api/audits/{id}/reports
```

enqueues:

```text
report_generation
```

The worker:

1. loads audit, inventory, findings, and artifact metadata;
2. builds `audit-report` v1;
3. validates JSON against the published schema;
4. renders self-contained HTML;
5. escapes all interpolated values;
6. writes JSON and HTML through `EvidenceStore`;
7. inserts a report-history row;
8. records a `source_hash`.

The report job uses an audit-level lock and the `report` resource group. It does not take an interface lock because it does not access the network.

## `source_hash`

`source_hash` represents the persisted input state rather than incidental fields of one rendering run.

If inventory, findings, scope, and evidence are unchanged, repeated generation should produce the same source hash even if these values change:

- report id;
- generation timestamp;
- job id;
- runtime metadata.

This makes it possible to tell whether two reports were actually generated from different audit content.

## Export API

Main endpoints:

```text
POST /api/audits/{id}/reports
GET  /api/audits/{id}/reports
GET  /api/audits/{id}/reports/{report_id}
GET  /api/audits/{id}/reports/{report_id}/export?format=json
GET  /api/audits/{id}/reports/{report_id}/export?format=html
```

PDF is not implemented yet:

```text
format=pdf → 422 pdf_not_available
```

Export resolves only artifact IDs already registered on the report row. `EvidenceStore.path_for` verifies that the resolved file remains below the configured evidence root.

## HTML

The HTML export is self-contained. It does not need the frontend bundle or follow-up API calls to display the report body.

Dynamic values are escaped before rendering so network-derived content such as hostnames, HTTP titles, or certificate subjects cannot turn into HTML/JavaScript injection inside the report.

## JSON

JSON is the machine-readable representation of the same audit state.

Stable keys and rule IDs remain English. Human-facing finding titles, descriptions, and recommendations may be Russian because the current operator UI and primary human report are aimed at Russian-speaking operators.

## Silent tap and unaddressed interfaces

A passive report can still be useful when the capture interface has no IPv4/IPv6 address.

`dumpcap` does not require an L3 address, so the report may still contain:

- frame count;
- quiet/active segment indication;
- actual 802.1Q tags;
- LLDP/CDP;
- STP;
- ARP;
- DHCP;
- mDNS/LLMNR/NBNS.

### Access-port VLANs

If a switch access port sends untagged frames, WireScope cannot honestly derive the VLAN ID from those frames alone.

The report therefore does not claim:

```text
VLAN 10 detected
```

unless `10` was actually present as an 802.1Q tag or reported separately as a neighbor fact.

Untagged traffic is still analyzed; the VLAN ID simply remains unknown.

An LLDP/CDP advertised native/voice VLAN is neighbor metadata, not proof that frames in the capture carried that 802.1Q tag. The report keeps those concepts separate.

## Active data in reports

Nmap-derived inventory appears only when active discovery really ran and persisted results.

If there is no usable L3 path, a passive-only audit remains valid. Reporting does not fabricate missing active data.

## Report history

Re-running report generation appends history rather than overwriting the previous export.

This is useful after:

- findings re-evaluation;
- moving a finding to accepted risk;
- inventory changes;
- new evidence artifacts;
- any need to compare with an earlier export.

## Testing

Reporting is fixture-based.

Tests cover:

- no live-network dependency;
- no scanner invocation during report generation;
- JSON Schema validation;
- HTML escaping;
- evidence path boundaries;
- stable source hashing.

A normal `pytest` run therefore does not contact a live network just to generate reports.

## Current limitations

- PDF export is not available;
- the human report does not yet have a fully localized multi-language template system; the primary narrative is Russian;
- the report references raw evidence by artifact ID/hash rather than attempting to embed every raw artifact into one file.
