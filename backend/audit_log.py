"""Small append-only operational audit log for operator actions.

The log deliberately stores request metadata only. Request bodies, passwords,
session cookies and provider output are never copied into this table.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any

from sqlalchemy import text

from persistence.database import Database


_AUDIT_ID = re.compile(r"^/api/audits/([^/]+)")


def _normalized_api_path(path: str) -> str:
    if path == "/api/v1":
        return "/api"
    if path.startswith("/api/v1/"):
        return "/api/" + path[len("/api/v1/") :]
    return path


class AuditLogService:
    def __init__(self, database: Database) -> None:
        self.database = database

    def record(
        self,
        *,
        action: str,
        method: str,
        path: str,
        status_code: int,
        actor: str | None,
        role: str | None,
        client_ip: str | None,
        audit_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        payload = json.dumps(
            details or {},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        with self.database.session() as session, session.begin():
            session.execute(
                text(
                    """
                    INSERT INTO operational_events (
                        created_at, actor, role, action, method, path,
                        status_code, client_ip, audit_id, details
                    ) VALUES (
                        :created_at, :actor, :role, :action, :method, :path,
                        :status_code, :client_ip, :audit_id, :details
                    )
                    """
                ),
                {
                    "created_at": datetime.now(timezone.utc),
                    "actor": actor,
                    "role": role,
                    "action": action,
                    "method": method.upper(),
                    "path": _normalized_api_path(path),
                    "status_code": int(status_code),
                    "client_ip": client_ip,
                    "audit_id": audit_id,
                    "details": payload,
                },
            )

    def list_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        actor: str | None = None,
        action: str | None = None,
        audit_id: str | None = None,
    ) -> dict[str, Any]:
        conditions: list[str] = []
        params: dict[str, Any] = {
            "limit": max(1, min(int(limit), 500)),
            "offset": max(0, int(offset)),
        }
        if actor:
            conditions.append("actor = :actor")
            params["actor"] = actor
        if action:
            conditions.append("action = :action")
            params["action"] = action
        if audit_id:
            conditions.append("audit_id = :audit_id")
            params["audit_id"] = audit_id
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

        with self.database.session() as session:
            rows = session.execute(
                text(
                    "SELECT id, created_at, actor, role, action, method, path, "
                    "status_code, client_ip, audit_id, details "
                    f"FROM operational_events{where} "
                    "ORDER BY id DESC LIMIT :limit OFFSET :offset"
                ),
                params,
            ).mappings().all()
            total = session.execute(
                text(f"SELECT COUNT(*) FROM operational_events{where}"),
                {key: value for key, value in params.items() if key not in {"limit", "offset"}},
            ).scalar_one()

        return {
            "items": [self._row(row) for row in rows],
            "limit": params["limit"],
            "offset": params["offset"],
            "total": int(total or 0),
        }

    def summary(self, *, limit: int = 20) -> dict[str, Any]:
        page = self.list_events(limit=limit)
        return {
            "total": page["total"],
            "recent": page["items"],
        }

    @staticmethod
    def _row(row: Any) -> dict[str, Any]:
        details = row["details"]
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except json.JSONDecodeError:
                details = {}
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "actor": row["actor"],
            "role": row["role"],
            "action": row["action"],
            "method": row["method"],
            "path": row["path"],
            "status_code": row["status_code"],
            "client_ip": row["client_ip"],
            "audit_id": row["audit_id"],
            "details": details or {},
        }


def operational_action(method: str, path: str) -> str | None:
    """Return a stable action name for requests worth keeping in the log."""
    method = method.upper()
    path = _normalized_api_path(path)
    if path == "/api/auth/login" and method == "POST":
        return "auth.login"
    if path == "/api/auth/logout" and method == "POST":
        return "auth.logout"
    if path == "/api/auth/password" and method == "POST":
        return "auth.password_change"
    if path.startswith("/api/network/") and method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "network.change"
    if path == "/api/audits" and method == "POST":
        return "audit.create"
    if path.startswith("/api/captures") and method == "POST":
        return "capture.change"
    if path.endswith("/retry") and path.startswith("/api/jobs/") and method == "POST":
        return "job.retry"
    if path.endswith("/cancel") and path.startswith("/api/jobs/") and method == "POST":
        return "job.cancel"
    if "/findings/" in path and method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "finding.change"
    if path.endswith("/findings") and method == "POST":
        return "findings.generate"
    if path.endswith("/reports") and method == "POST":
        return "report.generate"
    if "/reports/" in path and path.startswith("/api/audits/") and method == "DELETE":
        return "report.delete"
    if path.startswith("/api/maintenance/") and method == "POST":
        return "maintenance.cleanup"
    if path.startswith("/api/audits/") and method == "POST":
        if path.endswith("/passive"):
            return "audit.passive_start"
        if path.endswith("/discovery"):
            return "audit.discovery_start"
        if path.endswith("/protocol-audits"):
            return "audit.protocol_start"
        return "audit.change"
    if method in {"POST", "PUT", "PATCH", "DELETE"} and path.startswith("/api/"):
        return "api.mutation"
    return None


def audit_id_from_path(path: str) -> str | None:
    match = _AUDIT_ID.match(_normalized_api_path(path))
    return match.group(1) if match else None
