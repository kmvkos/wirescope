# WireScope reporting

[Русский](../REPORTING_MODEL.md) · **English**

A WireScope report is built only from persisted audit state. Report generation does not re-run Nmap, protocol modules, or passive capture.

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
audit-report v1
        ↓
JSON
├── self-contained HTML
└── Markdown
```

JSON `audit-report` v1 remains the canonical document. HTML and Markdown are views over the same persisted state.

Schema:

```text
reports/schema/audit-report-v1.json
```

## Report contents

### Executive summary

Includes:

- asset/service/finding counts;
- open findings;
- highest open severity;
- headline and short summary;
- basic passive metrics.

Narrative text is deterministic and derived from persisted data. An LLM is not used to invent CVEs or missing facts.

### Environment and scope

The report records the environment snapshot, capture interface, and confirmed active scope. Missing L3 connectivity does not invalidate a passive-only report.

### Passive data

Includes frame count, visibility/segment notes, 802.1Q tags actually observed, LLDP/CDP, STP, ARP/DHCP, and other normalized passive observations.

Untagged traffic does not receive an invented VLAN ID. LLDP/CDP native or voice VLAN values remain neighbor metadata.

### Inventory

Assets and services come from persisted inventory together with available vendor, OS, and device-class hints.

### Findings

Open, suppressed, and accepted-risk findings are retained so exported reports preserve operator decisions. Recommendations are derived from current findings.

### Evidence references

Raw PCAP/XML/stdout is not embedded in the main report. Evidence metadata includes:

- artifact id;
- artifact type;
- content type;
- size;
- SHA-256.

Internal filesystem `relative_path` values are not exposed in the public report.

## Generation

```text
POST /api/v1/audits/{id}/reports
```

enqueues a durable `report_generation` job.

The worker:

1. loads persisted audit state;
2. builds `audit-report` v1;
3. validates the document;
4. renders self-contained HTML;
5. writes JSON and HTML through `EvidenceStore`;
6. inserts a report-history row;
7. records `source_hash`.

Report generation does not need an interface lock because it does not touch the network.

## `source_hash`

`source_hash` reflects persisted source state rather than report id, generation timestamp, or job id.

If inventory, findings, scope, and evidence are unchanged, repeated generation should retain the same source hash.

## Export API

```text
GET /api/v1/audits/{id}/reports/{report_id}/export?format=json
GET /api/v1/audits/{id}/reports/{report_id}/export?format=html
GET /api/v1/audits/{id}/reports/{report_id}/export?format=markdown
```

`format=md` is accepted as an alias for Markdown.

PDF is not implemented yet:

```text
format=pdf → 422 pdf_not_available
```

## HTML

HTML is self-contained and requires neither the frontend bundle nor follow-up API calls to display the report body. Dynamic values are escaped so network-derived hostnames, HTTP titles, certificate subjects, and similar data cannot become HTML/JavaScript injection.

## JSON

JSON is the stable machine-readable `audit-report` v1 and the source of truth for other export formats.

Schema keys and rule IDs remain stable. Human-facing titles, descriptions, and recommendations may be Russian.

## Markdown

Markdown is rendered from the persisted JSON report and does not create another scanner stage.

It includes:

- audit metadata;
- executive summary;
- scope;
- passive summary;
- assets;
- services;
- findings;
- recommendations;
- evidence references.

It is intended for Git, issue trackers, wiki/Confluence-style systems, and manual inclusion in technical documentation.

## Evidence access

Evidence may be inspected separately from report exports through audit-scoped routes:

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

The backend verifies that an artifact belongs to the requested audit before returning it. Artifact responses include `X-WireScope-SHA256`.

## Report history

A new generation appends history rather than overwriting the previous report. This supports comparisons after findings re-evaluation, accepted-risk changes, inventory changes, or new evidence.

## Testing

Reporting tests are fixture-based and do not require a live network. They cover schema validation, HTML escaping, evidence path boundaries, source-hash stability, and Markdown rendering.

## Current limitations

- PDF export is not available;
- there is no separate multi-language human-report template system yet;
- raw evidence remains referenced by artifact id/hash instead of being embedded into one giant file.
