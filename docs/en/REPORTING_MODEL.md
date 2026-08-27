# WireScope reporting

[Русский](../REPORTING_MODEL.md) · **English**

WireScope reports are built only from persisted audit state. Report generation and export do not re-run Nmap, protocol modules, or passive capture.

```text
audit metadata
+ environment snapshot
+ confirmed scope
+ passive result / assessment
+ inventory
+ findings
+ artifact metadata
        ↓
audit-report v1 JSON   ← canonical document
        ↓
        ├── human-readable HTML
        └── Markdown for Git/wiki/tickets
```

Canonical schema:

```text
reports/schema/audit-report-v1.json
```

## Core rule

JSON keeps stable machine values and remains the source of truth. Human-facing HTML and Markdown can improve without changing the schema or report `source_hash`.

## Audit Report ownership

Audit Report is the **source-of-truth for the audit itself**. It owns:

- inventory and discovered services;
- protocol-audit observations;
- findings, severity/confidence/status;
- rationale and recommendations;
- audit evidence and confirmed scope;
- concise passive visibility collected as part of the audit pipeline.

A separate PCAP Traffic Analysis is not automatically embedded into Audit Report and must not be reproduced there in full. Its role is to describe a specific capture window, communications, protocol visibility, and network diagnostics.

Audit passive context and standalone Traffic Analysis can use related network primitives such as ARP/DHCP, but they answer different questions:

- **Audit passive** explains which evidence described the local environment and supported safe audit scoping;
- **Traffic Analysis** owns detailed diagnostics and protocol visibility for a retained PCAP.

PCAP-specific rates, top talkers, communications graph, TCP health, DNS latency, and detailed Protocol Intelligence do not belong to Audit Report.

See [PRODUCT_COHERENCE.md](PRODUCT_COHERENCE.md) for the product-wide ownership and deduplication contract.

## Operator-facing structure

The HTML report follows the decision flow:

1. **Audit result** — concise conclusion, highest open severity, and key counts.
2. **Detected problems** — what was detected, why it matters, and what should be done.
3. **Action plan** — prioritized recommendations.
4. **Scope** — what was authorized for checking.
5. **Assets and services** — inventory.
6. **Passive observations** — audit-context evidence about the local segment, not a copy of standalone Traffic Analysis.
7. **Technical data** — evidence, hashes, metadata, and warnings.

## Executive summary

The canonical summary contains asset/service/finding counts, open finding count, highest open severity, headline, deterministic conclusion, and only the passive metrics required for audit context.

Narrative is derived from persisted data. An LLM is not used to invent CVEs, causes, or missing facts.

When no findings exist, the human report states that this applies only to checks that actually ran and is not proof of absolute security.

## Scope and passive data

The report records environment snapshot, capture interface, and confirmed active scope.

Passive sections include frame count, visibility/segment state, observed 802.1Q tags, ARP/DHCP, and other normalized observations relevant to audit context. Untagged traffic never receives an invented VLAN ID.

This section must not become a standalone Traffic Analysis. PCAP-specific rates, top talkers, communications, latency, and detailed protocol intelligence stay with Traffic Analysis.

## Inventory

Assets and services come from persisted inventory together with available vendor, OS, and device-class hints. Human presentation may localize labels while JSON machine values remain unchanged.

## Findings

Canonical reports retain open, suppressed, and accepted-risk findings so operator decisions are not lost.

HTML and Markdown separate observed condition, security relevance, and recommended action.

**Security rationale and remediation have one owner: Findings/Audit Report.** Mere Telnet/FTP/HTTP presence in a standalone PCAP remains a Traffic Analysis observation and must not become a second finding solely because the protocol was visible.

Raw provider stdout is never embedded in finding narrative.

## Evidence references

PCAP/XML/stdout is not embedded into the main narrative. Evidence metadata includes artifact id/type, content type, size, and SHA-256. Public report documents do not expose filesystem `relative_path` values.

## Relationship to other views

### Traffic Analysis

Owns one capture window: traffic metrics, conversations, protocol visibility, and network diagnostics. It does not duplicate Audit Findings/rationale/recommendations.

### Network Topology

Owns structure, relationships, and claimability. Finding/service badges are valid context but not a copy of Audit Report.

### Correlated Assessment

Owns cross-source relationships only. It may state that a discovered service was observed in the selected PCAP or that a finding belongs to a traffic-visible asset, while full source detail remains in Audit Report/Traffic Analysis.

### Dashboard

Provides compact status, counts, and navigation. It is not another report renderer.

## Generation

```text
POST /api/v1/audits/{id}/reports
```

enqueues a durable `report_generation` job. The worker loads persisted audit state, builds and validates `audit-report` v1, renders self-contained HTML, stores report artifacts/history, and records `source_hash`. Report generation does not require a network/interface lock.

## Export API

```text
GET /api/v1/audits/{id}/reports/{report_id}/export?format=json
GET /api/v1/audits/{id}/reports/{report_id}/export?format=html
GET /api/v1/audits/{id}/reports/{report_id}/export?format=markdown
```

`format=md` aliases Markdown.

### JSON

Returns persisted canonical `audit-report v1`.

### HTML

HTML is rendered from persisted canonical JSON using the current human-presentation renderer, so old reports can receive presentation improvements without re-running the audit. Historical HTML artifacts remain immutable.

### Markdown

Markdown is rendered from the same canonical JSON and follows the same ownership model.

## `source_hash`

`source_hash` reflects persisted audit state rather than CSS, localization, report id, or export time. Presentation-only changes do not change the factual audit result.

## HTML safety

Network-derived values are untrusted. The renderer escapes dynamic content and never embeds raw provider output as executable HTML. Tests cover XSS escaping and filesystem-path boundaries.

## PDF

PDF is not implemented:

```text
format=pdf → 422 pdf_not_available
```

Self-contained HTML already includes print layout and can be printed through the browser.
