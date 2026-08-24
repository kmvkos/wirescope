# WireScope API

[Русский](../API.md)

## Versioning

The canonical WireScope HTTP API is published under `/api/v1`.

For example:

```text
GET  /api/v1/health
GET  /api/v1/environment
POST /api/v1/audits
GET  /api/v1/jobs/{job_id}
```

The old `/api` prefix is temporarily kept as a compatibility alias. This lets the current GUI and external clients migrate to v1 without requiring every component to change at once.

```text
/api/v1/...   canonical API
/api/...      temporary compatibility alias
```

Compatibility routes are intentionally hidden from OpenAPI. Swagger and ReDoc show only `/api/v1/*`.

## Compatibility

During the transition both prefixes call the same handlers and use the same models, authorization rules, and scope checks. There is no separate legacy implementation to maintain.

Some response-generated links (`result_url`, `pcap_url`, report export URLs) still use `/api/*`. They remain valid through the compatibility alias. Those links can move to `/api/v1` separately after the frontend has migrated.

## Authentication and authorization

Authorization semantics are identical for both prefixes:

- `GET /health`, `/status`, and `/ready` are public;
- `POST /auth/login` and `/auth/logout` are public;
- other operational routes require a session;
- mutating routes require the `auditor` role, except changing the signed-in user's own password.

Sessions use an HttpOnly cookie. See [SECURITY_MODEL.md](SECURITY_MODEL.md) for the full trust model.

## Change policy

Compatible additions may be made inside `/api/v1`. A breaking contract change should receive a new major API version instead of silently changing an existing v1 route.
