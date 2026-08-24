# WireScope API

[Русский](../API.md)

WireScope publishes its canonical HTTP API under `/api/v1`. The old `/api/*` prefix remains as a hidden compatibility alias while the existing frontend and external clients migrate.

```text
/api/v1/...   canonical contract
/api/...      transitional compatibility alias
```

Only `/api/v1` is exposed in OpenAPI/Swagger.

## System endpoints

```text
GET /api/v1/health
GET /api/v1/status
GET /api/v1/ready
GET /api/v1/environment
GET /api/v1/interfaces
GET /api/v1/capabilities
GET /api/v1/scan-profiles
```

`/health` answers whether the API process is alive. `/ready` checks SQLite, migration state, the worker, and the core packet-capture tools `dumpcap` and `tshark`.

Missing optional providers such as `ssh-audit`, `smbclient`, or even Nmap no longer make the entire appliance `not_ready`. `/capabilities` reports the full tool and feature inventory.

`/scan-profiles` returns the declarative `discovery`, `standard`, and `deep` profiles that are actually loaded. The API does not accept arbitrary Nmap flag strings.

## Audits and pipeline

```text
POST /api/v1/audits
GET  /api/v1/audits
GET  /api/v1/audits/{audit_id}
POST /api/v1/audits/{audit_id}/passive
POST /api/v1/audits/{audit_id}/discovery
POST /api/v1/audits/{audit_id}/protocol-audits
POST /api/v1/audits/{audit_id}/findings
POST /api/v1/audits/{audit_id}/reports
```

Additional read-only views:

```text
GET /api/v1/audits/{audit_id}/dashboard
GET /api/v1/audits/{audit_id}/correlations
GET /api/v1/audits/{audit_id}/diff?against={previous_audit_id}
```

`dashboard` is computed from existing jobs, inventory, and findings. There is no separate dashboard database.

`correlations` explains which identity signals connected passive and active observations to an asset: MAC, IP, name source, Nmap, and related evidence. A hostname by itself is not used to merge two assets automatically.

`diff` compares two persisted audits and reports added/removed assets, open services, and findings. Stable identity prefers MAC, then IP, with a name used only as a last fallback. Findings on different services of the same asset remain distinct.

## Inventory

```text
GET /api/v1/audits/{audit_id}/assets
GET /api/v1/audits/{audit_id}/assets/{asset_id}
GET /api/v1/audits/{audit_id}/services
GET /api/v1/audits/{audit_id}/inventory
GET /api/v1/audits/{audit_id}/observations
```

Inventory remains the normalized source of truth. Device classification (`server-like`, `workstation-like`, `network-device-like`, `printer-like`, `iot-like`, `unknown`) is a confidence-rated hint with source signals, not a finding.

## Jobs

```text
GET  /api/v1/jobs
GET  /api/v1/jobs/{job_id}
POST /api/v1/jobs/{job_id}/cancel
GET  /api/v1/jobs/{job_id}/events
GET  /api/v1/jobs/{job_id}/result
```

Job status is kept separate from larger result artifacts, so job listings do not pull raw provider output into every response.

## Evidence

A finding can expose its registered evidence artifacts through:

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
```

Artifact content uses an audit-scoped URL:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

WireScope verifies that the artifact belongs to the requested audit before returning it. Text, JSON, and XML evidence may be rendered inline; binary content is returned as an attachment. Responses include `X-WireScope-SHA256`.

## Reports

```text
GET /api/v1/audits/{audit_id}/reports
GET /api/v1/audits/{audit_id}/reports/{report_id}
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=json
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=html
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=markdown
```

JSON `audit-report` v1 remains the canonical report document. HTML and Markdown are views over the same persisted data. Exporting a report does not re-run scanners.

`format=md` is accepted as a short alias for Markdown. PDF export is not implemented yet.

## Authentication and authorization

Public routes are:

- `GET /health`, `/status`, `/ready`;
- `POST /auth/login`, `/auth/logout`.

Other routes require a local session. Mutating endpoints require the `auditor` role. A `viewer` may read inventory, findings, reports, capabilities, diffs, and evidence.

Sessions use an HttpOnly cookie. See [SECURITY_MODEL.md](SECURITY_MODEL.md).

## v1 compatibility policy

Compatible additions such as new endpoints or optional fields may be added inside `/api/v1`. A change that breaks an existing request or response contract should receive a new major API version instead of silently changing v1.
