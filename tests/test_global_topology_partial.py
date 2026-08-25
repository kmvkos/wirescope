from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from jobs.models import AuditStatus
import topology.global_view as global_view


def _audit(audit_id: str, *, status: AuditStatus = AuditStatus.COMPLETED):
    return SimpleNamespace(
        id=audit_id,
        profile="deep",
        interface="eth0",
        status=status,
        created_at=datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc),
    )


def test_global_topology_reports_failed_sources_without_dropping_good_audits(monkeypatch):
    good = _audit("audit-good")
    broken = _audit("audit-broken")
    queued = _audit("audit-queued", status=AuditStatus.RUNNING)
    services = SimpleNamespace(
        jobs=SimpleNamespace(
            list_audits=lambda **_kwargs: SimpleNamespace(items=[good, broken, queued])
        )
    )

    def fake_build_topology(_services, audit_id: str):
        if audit_id == broken.id:
            raise RuntimeError("internal database path must not leak")
        return {
            "nodes": [
                {
                    "id": "asset:gateway",
                    "label": "core-router",
                    "addresses": ["192.0.2.1"],
                }
            ],
            "segments": [
                {
                    "id": "segment:192.0.2.0/24",
                    "network": "192.0.2.0/24",
                    "family": 4,
                    "members": ["asset:host"],
                    "gateways": ["192.0.2.1"],
                }
            ],
        }

    monkeypatch.setattr(global_view, "build_topology", fake_build_topology)
    result = global_view.build_global_topology(services)

    assert result["partial"] is True
    assert result["schema_version"] == 2
    assert result["summary"]["audits_considered"] == 2
    assert result["summary"]["audits"] == 1
    assert result["summary"]["source_errors"] == 1
    assert result["segments"][0]["network"] == "192.0.2.0/24"
    assert result["audits"][0]["id"] == good.id
    assert result["source_errors"] == [
        {
            "audit_id": broken.id,
            "profile": "deep",
            "interface": "eth0",
            "status": "completed",
            "component": "topology",
            "code": "source_unavailable",
            "error_type": "RuntimeError",
        }
    ]
    assert "internal database path" not in repr(result)
    assert any("неполная" in warning.lower() for warning in result["warnings"])


def test_global_topology_without_source_errors_is_not_partial(monkeypatch):
    audit = _audit("audit-empty")
    services = SimpleNamespace(
        jobs=SimpleNamespace(
            list_audits=lambda **_kwargs: SimpleNamespace(items=[audit])
        )
    )
    monkeypatch.setattr(
        global_view,
        "build_topology",
        lambda _services, _audit_id: {"nodes": [], "segments": []},
    )

    result = global_view.build_global_topology(services)

    assert result["partial"] is False
    assert result["source_errors"] == []
    assert result["summary"]["audits_considered"] == 1
    assert result["summary"]["source_errors"] == 0
