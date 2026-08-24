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

JSON keeps stable machine values and remains the source of truth. Human-facing HTML and Markdown can improve without changing the schema or the report `source_hash`.

For example, the machine value `high` remains `high` in JSON while the Russian operator report displays **«Высокая»**. Profiles, statuses, confidence values, device classes, and headline tokens are localized the same way.

This keeps external integrations stable while allowing the presentation layer to improve.

## Operator-facing structure

The HTML report follows the order in which a human normally makes a decision:

1. **Audit result** — concise conclusion, highest open severity, and key counts.
2. **Detected problems** — each finding is explained as:
   - what was detected;
   - why it matters;
   - what should be done.
3. **Action plan** — prioritized recommendations.
4. **Scope** — what was actually authorized for checking.
5. **Assets and services** — inventory.
6. **Passive observations** — what WireScope actually observed on the segment.
7. **Technical data** — evidence, hashes, metadata, and warnings.

Evidence IDs and internal technical detail are intentionally kept out of the opening summary while remaining available for verification.

## Executive summary

The canonical summary contains:

- asset/service/finding counts;
- open finding count;
- highest open severity;
- a headline token;
- a deterministic Russian conclusion;
- core passive metrics.

Narrative text is derived from persisted data. An LLM is not used to invent CVEs, causes, or missing facts.

When no findings exist, the human report explicitly states that this conclusion applies only to checks that actually ran and is not proof of absolute security.

## Scope and passive data

The report records the environment snapshot, capture interface, and confirmed active scope.

Passive sections include frame count, visibility/segment state, 802.1Q tags actually observed, ARP/DHCP, and other normalized observations.

Untagged traffic does not receive an invented VLAN ID, and the human report explains that limitation directly.

## Inventory

Assets and services come from persisted inventory together with available vendor, OS, and device-class hints.

The Russian presentation translates machine values such as:

```text
server-like          → Сервер
workstation-like     → Рабочая станция
network-device-like  → Сетевое устройство
printer-like         → Принтер / МФУ
iot-like             → IoT / встроенное устройство
```

The JSON machine values remain unchanged.

## Findings

Canonical reports retain open, suppressed, and accepted-risk findings so operator decisions are not lost.

HTML and Markdown show severity/confidence/status using clear Russian labels and separate:

- observed condition;
- security relevance;
- recommended action.

Raw provider stdout is not embedded in finding narrative.

## Evidence references

PCAP/XML/stdout is not embedded into the main narrative. Evidence metadata includes:

- artifact id;
- artifact type;
- content type;
- size;
- SHA-256.

Public report documents do not expose filesystem `relative_path` values.

## Generation

```text
POST /api/v1/audits/{id}/reports
```

enqueues a durable `report_generation` job.

The worker:

1. loads persisted audit state;
2. builds `audit-report` v1;
3. validates canonical JSON;
4. renders self-contained HTML;
5. stores JSON and HTML report artifacts;
6. appends report history;
7. records `source_hash`.

Report generation does not require a network/interface lock.

## Export API

```text
GET /api/v1/audits/{id}/reports/{report_id}/export?format=json
GET /api/v1/audits/{id}/reports/{report_id}/export?format=html
GET /api/v1/audits/{id}/reports/{report_id}/export?format=markdown
```

`format=md` is an alias for Markdown.

### JSON

Returns the persisted canonical `audit-report v1` document.

### HTML

When opened, HTML is rendered from persisted canonical JSON using the current human-presentation renderer. Therefore **older saved reports automatically receive the current design and localization without re-running the audit**.

The historical HTML artifact created by the report job remains immutable and is not rewritten.

The rendered HTML is self-contained, responsive, print-friendly, and independent of the WireScope frontend bundle. All network-derived values are escaped before insertion.

### Markdown

Markdown is also rendered from canonical JSON and is Russian-first for the appliance operator. It is intended for Git, issue trackers, wiki systems, and technical documentation.

## `source_hash`

`source_hash` reflects persisted audit state rather than CSS, localization, report id, or export time.

Presentation-only changes do not change the factual audit result.

## HTML safety

Hostnames, service banners, certificate subjects, finding titles, and similar values may originate from an untrusted network. The renderer escapes dynamic content and never embeds raw provider output as executable HTML.

Tests explicitly cover XSS escaping and filesystem-path boundaries.

## PDF

PDF is not implemented yet:

```text
format=pdf → 422 pdf_not_available
```

It is not a v1.0 blocker: the self-contained HTML renderer includes a print layout and can be printed through the browser.
