# WireScope reporting model

Milestone 6 adds **audit reporting**. A report is a versioned view of
persisted audit data. It does not start scanners, parse tool stdout, or
follow caller-supplied filesystem paths.

```text
audit + environment snapshot
confirmed scope
assets / services
findings + recommendations
artifact metadata (ids, types, hashes)
        ↓
Versioned report view model (schema audit-report v1)
        ↓
Self-contained HTML  +  normalized JSON
        ↓
Evidence-store artifacts + reports history row
```

PDF export is deferred until the HTML contract stabilizes.

## Report contract

Schema name `audit-report`, version 1. Published JSON Schema:
`reports/schema/audit-report-v1.json`.

Sections:

- executive summary (counts, highest open severity, headline);
- environment (hostname, interfaces, default route, DNS);
- scope (confirmed snapshot plus the audit scope object);
- assets and services;
- findings (including suppressed and accepted-risk rows);
- recommendations derived from **open** findings;
- evidence references (artifact id, type, content type, size, SHA-256);
- audit metadata (product, versions, source hash, job/actor).

Raw provider output stays in the evidence store. The human report and JSON
export list identifiers and hashes only. Filesystem `relative_path` values are
not exported.

## Generation

`POST /api/audits/{id}/reports` enqueues `report_generation`. The worker
takes exclusive `audit:<id>` plus group `report` (default max 1). It does
**not** take `interface:<name>` and does not invoke `ToolRunner`.

Each successful job:

1. loads persisted rows and registered artifacts;
2. builds the versioned view model;
3. validates JSON against the published schema;
4. renders self-contained HTML with every interpolated value escaped;
5. writes JSON and HTML through `EvidenceStore` (UUID paths, `0600`, SHA-256);
6. inserts a `reports` history row with generation metadata and `source_hash`.

Re-running the job appends history. Identical persisted inventory, findings,
scope, and evidence inputs produce the same `source_hash` even when report
identity, generation time, job id, or the last job's audit summary change.

## API

- `POST /api/audits/{id}/reports` — enqueue generation;
- `GET /api/audits/{id}/reports` — paginated history;
- `GET /api/audits/{id}/reports/{report_id}` — metadata and export URLs;
- `GET /api/audits/{id}/reports/{report_id}/export?format=json|html`.

`format=pdf` returns `422 pdf_not_available`. Export endpoints resolve
artifact ids from the report row and read only through `EvidenceStore.path_for`,
which rejects paths outside the evidence root.

Default tests stay fixture-based (`pytest -m not network`). Report generation
never contacts a live network.
