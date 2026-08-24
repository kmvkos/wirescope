# WireScope API

[Русский](../API.md)

WireScope publishes its canonical HTTP API under `/api/v1`. The old `/api/*` prefix remains as a hidden compatibility alias for existing installations and clients.

```text
/api/v1/...   canonical contract
/api/...      transitional compatibility alias
```

Only `/api/v1` is shown in OpenAPI/Swagger.

## System state

```text
GET /api/v1/health
GET /api/v1/status
GET /api/v1/ready
GET /api/v1/environment
GET /api/v1/interfaces
GET /api/v1/capabilities
GET /api/v1/scan-profiles
GET /api/v1/diagnostics
GET /api/v1/diagnostics/export
```

`/health` answers only whether the API process is alive. `/ready` checks SQLite, migration state, the worker, and the core `dumpcap`/`tshark` tools.

A missing optional provider such as `ssh-audit` or `smbclient` does not make the whole appliance `not_ready`. `/capabilities` reports the complete feature/tool inventory.

`/diagnostics` is the operational snapshot: version/platform, listener, runtime checks, capabilities, SQLite `quick_check`, disk/evidence usage, retention, and recent operational events. `/diagnostics/export` returns the same safe snapshot as a JSON attachment. These routes are auditor-only.

`/scan-profiles` returns the loaded declarative `discovery`, `standard`, and `deep` profiles. Arbitrary Nmap flag strings are not accepted.

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

`dashboard` is derived from existing jobs, inventory, and findings; there is no separate dashboard database.

`correlations` explains which passive and active identity signals support an asset. A hostname alone is not enough to merge assets automatically.

`diff` compares persisted audits and reports added/removed assets, open services, and findings.

## Inventory

```text
GET /api/v1/audits/{audit_id}/assets
GET /api/v1/audits/{audit_id}/assets/{asset_id}
GET /api/v1/audits/{audit_id}/services
GET /api/v1/audits/{audit_id}/inventory
GET /api/v1/audits/{audit_id}/observations
```

Inventory remains the normalized source of truth. Device classification (`server-like`, `workstation-like`, `network-device-like`, `printer-like`, `iot-like`, `unknown`) is a confidence-rated hint, not a finding.

## Jobs and recovery

```text
GET  /api/v1/jobs
GET  /api/v1/jobs/{job_id}
POST /api/v1/jobs/{job_id}/cancel
POST /api/v1/jobs/{job_id}/retry
GET  /api/v1/jobs/{job_id}/events
GET  /api/v1/jobs/{job_id}/result
```

`retry` is allowed only for `failed`, `interrupted`, and `cancelled` jobs. The historical job remains immutable; WireScope creates a new queued job with the same parameters and links the two through job events.

Recovery is stage-level. WireScope does not attempt to resume a dead subprocess from an arbitrary internal execution point.

## Evidence

Finding evidence:

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
```

Artifact content is available only through the audit-scoped route:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

WireScope verifies audit ownership before returning content. Text/JSON/XML may be rendered inline; binary data is returned as an attachment. Responses include `X-WireScope-SHA256`.

## Reports

```text
GET /api/v1/audits/{audit_id}/reports
GET /api/v1/audits/{audit_id}/reports/{report_id}
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=json
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=html
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=markdown
```

JSON `audit-report` v1 remains canonical. HTML and Markdown are rendered from the same persisted data and do not re-run scanners. `format=md` aliases Markdown. PDF is not part of the v1 release gate.

## Operational audit log

```text
GET /api/v1/audit-log
```

Auditor-only. Filters include `actor`, `action`, `audit_id`, `limit`, and `offset`.

Significant mutations are recorded: login/logout/password change, audit creation/stage starts, cancel/retry, network changes, finding changes, report generation, and maintenance cleanup.

The log stores request metadata but **never** request bodies, passwords, session cookies, or provider stdout.

## Lifecycle and retention

```text
GET  /api/v1/maintenance/status
POST /api/v1/maintenance/cleanup
```

`maintenance/status` exposes filesystem/evidence usage, SQLite state, and the current retention policy.

Cleanup is explicitly two-step:

```json
{"confirm": false, "include_raw": true}
```

returns a preview without deleting anything.

```json
{"confirm": true, "include_raw": true}
```

allows aged raw evidence to be removed according to policy. Normalized inventory, findings, and reports are not automatically deleted.

Default retention:

- temporary: 24 hours;
- debug: 7 days;
- PCAP: 30 days;
- Nmap XML / protocol raw output: 90 days.

## Authentication and authorization

Public routes:

- `GET /health`, `/status`, `/ready`;
- `POST /auth/login`, `/auth/logout`.

Other routes require a local session. Normal mutating routes require `auditor`; a `viewer` can read audits, inventory, findings, reports, diffs, and evidence. Operational audit log, diagnostics, and maintenance are auditor-only.

Sessions use an HttpOnly cookie. See [SECURITY_MODEL.md](SECURITY_MODEL.md).

## v1 compatibility policy

Compatible additions such as new optional fields and new endpoints may be added inside `/api/v1`. A breaking request/response change requires a new major API version rather than silently changing v1.

The release gate for `v1.0.0-rc1` is documented in [RELEASE_READINESS.md](RELEASE_READINESS.md).
