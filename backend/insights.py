"""Read-only aggregate views built from persisted WireScope data."""

from __future__ import annotations

from collections import Counter
from typing import Any

from findings.models import FindingStatus


_PIPELINE_TYPES = (
    ("passive", {"passive", "passive_discovery"}),
    ("discovery", {"discovery", "active_discovery"}),
    ("protocol", {"protocol", "protocol_audit"}),
    ("findings", {"findings", "findings_evaluation"}),
    ("report", {"report", "report_generation"}),
)


def _all_assets(inventory, audit_id: str) -> list[Any]:
    result: list[Any] = []
    offset = 0
    while True:
        page = inventory.list_assets(
            audit_id=audit_id,
            limit=500,
            offset=offset,
            include_services=True,
        )
        result.extend(page.items)
        offset += len(page.items)
        if not page.items or offset >= page.total:
            return result


def _all_services(inventory, audit_id: str) -> list[Any]:
    result: list[Any] = []
    offset = 0
    while True:
        page = inventory.list_services(
            audit_id=audit_id,
            limit=500,
            offset=offset,
        )
        result.extend(page.items)
        offset += len(page.items)
        if not page.items or offset >= page.total:
            return result


def _all_findings(store, audit_id: str) -> list[Any]:
    result: list[Any] = []
    offset = 0
    while True:
        page = store.list_findings(audit_id=audit_id, limit=500, offset=offset)
        result.extend(page.items)
        offset += len(page.items)
        if not page.items or offset >= page.total:
            return result


def _asset_identity(asset: Any) -> str:
    mac = str(getattr(asset, "mac", "") or "").strip().lower()
    if mac:
        return f"mac:{mac}"
    addresses = sorted(
        str(item.address)
        for item in (getattr(asset, "addresses", None) or [])
        if getattr(item, "address", None)
    )
    if addresses:
        return f"ip:{addresses[0]}"
    names = sorted(
        str(item.name).lower()
        for item in (getattr(asset, "names", None) or [])
        if getattr(item, "name", None)
    )
    if names:
        return f"name:{names[0]}"
    return f"asset:{getattr(asset, 'id', 'unknown')}"


def _asset_label(asset: Any) -> str:
    names = [
        str(item.name)
        for item in (getattr(asset, "names", None) or [])
        if getattr(item, "name", None)
    ]
    addresses = [
        str(item.address)
        for item in (getattr(asset, "addresses", None) or [])
        if getattr(item, "address", None)
    ]
    fallback = str(getattr(asset, "mac", None) or getattr(asset, "id", "unknown"))
    return (names or addresses or [fallback])[0]


def dashboard(services, audit_id: str) -> dict[str, Any]:
    audit = services.jobs.get_audit(audit_id)
    inventory_summary = services.inventory.summary(audit_id)
    findings_by_severity = services.findings.counts_by_severity(audit_id)
    findings_by_status = {
        status.value: services.findings.list_findings(
            audit_id=audit_id,
            limit=1,
            offset=0,
            status=status,
        ).total
        for status in FindingStatus
    }
    jobs_page = services.jobs.list_jobs(limit=500, offset=0, audit_id=audit_id)
    jobs = list(jobs_page.items)

    pipeline: list[dict[str, Any]] = []
    for stage, aliases in _PIPELINE_TYPES:
        matches = [job for job in jobs if job.type in aliases]
        latest = max(matches, key=lambda item: item.created_at) if matches else None
        pipeline.append(
            {
                "stage": stage,
                "status": getattr(getattr(latest, "status", None), "value", None),
                "progress": getattr(latest, "progress", None),
                "message": getattr(latest, "message", None),
                "job_id": getattr(latest, "id", None),
            }
        )

    service_page = _all_services(services.inventory, audit_id)
    common_services = Counter(
        (item.service_name or f"{item.protocol}/{item.port}")
        for item in service_page
        if item.state in {"open", "open|filtered"}
    )

    return {
        "audit": {
            "id": audit.id,
            "status": getattr(audit.status, "value", audit.status),
            "profile": audit.profile,
            "interface": audit.interface,
            "created_at": audit.created_at,
            "finished_at": audit.finished_at,
        },
        "inventory": inventory_summary.model_dump(mode="json"),
        "findings": {
            "total": services.findings.count(audit_id),
            "by_severity": findings_by_severity,
            "by_status": findings_by_status,
        },
        "pipeline": pipeline,
        "common_services": [
            {"name": name, "count": count}
            for name, count in common_services.most_common(10)
        ],
    }


def audit_diff(services, base_audit_id: str, compare_audit_id: str) -> dict[str, Any]:
    services.jobs.get_audit(base_audit_id)
    services.jobs.get_audit(compare_audit_id)

    base_assets = _all_assets(services.inventory, base_audit_id)
    next_assets = _all_assets(services.inventory, compare_audit_id)
    base_asset_map = {_asset_identity(item): item for item in base_assets}
    next_asset_map = {_asset_identity(item): item for item in next_assets}

    base_id_to_identity = {item.id: key for key, item in base_asset_map.items()}
    next_id_to_identity = {item.id: key for key, item in next_asset_map.items()}

    def service_key(item: Any, id_map: dict[str, str]) -> tuple[str, str, int]:
        return (
            id_map.get(item.asset_id, f"asset:{item.asset_id}"),
            str(item.protocol),
            int(item.port),
        )

    base_services = {
        service_key(item, base_id_to_identity): item
        for item in _all_services(services.inventory, base_audit_id)
        if item.state in {"open", "open|filtered"}
    }
    next_services = {
        service_key(item, next_id_to_identity): item
        for item in _all_services(services.inventory, compare_audit_id)
        if item.state in {"open", "open|filtered"}
    }
    base_service_id_to_identity = {
        item.id: service_key(item, base_id_to_identity)
        for item in base_services.values()
    }
    next_service_id_to_identity = {
        item.id: service_key(item, next_id_to_identity)
        for item in next_services.values()
    }

    def finding_key(
        item: Any,
        asset_map: dict[str, str],
        service_map: dict[str, tuple[str, str, int]],
    ) -> tuple[str, str, str, str]:
        asset_identity = (
            asset_map.get(str(item.asset_id), f"asset:{item.asset_id}")
            if item.asset_id
            else "none"
        )
        endpoint = service_map.get(str(item.service_id)) if item.service_id else None
        service_identity = (
            f"{endpoint[0]}:{endpoint[1]}/{endpoint[2]}"
            if endpoint is not None
            else "none"
        )
        return str(item.rule_id), asset_identity, service_identity, str(item.family)

    base_findings = {
        finding_key(item, base_id_to_identity, base_service_id_to_identity): item
        for item in _all_findings(services.findings, base_audit_id)
    }
    next_findings = {
        finding_key(item, next_id_to_identity, next_service_id_to_identity): item
        for item in _all_findings(services.findings, compare_audit_id)
    }

    def service_payload(key: tuple[str, str, int], item: Any) -> dict[str, Any]:
        return {
            "asset": key[0],
            "protocol": key[1],
            "port": key[2],
            "service": item.service_name,
            "product": item.product,
        }

    def finding_payload(key: tuple[str, str, str, str], item: Any) -> dict[str, Any]:
        return {
            "rule_id": key[0],
            "asset": key[1],
            "service": key[2],
            "family": key[3],
            "title": item.title,
            "severity": getattr(item.severity, "value", item.severity),
            "status": getattr(item.status, "value", item.status),
        }

    return {
        "base_audit_id": base_audit_id,
        "compare_audit_id": compare_audit_id,
        "assets": {
            "added": [
                {"identity": key, "label": _asset_label(next_asset_map[key])}
                for key in sorted(next_asset_map.keys() - base_asset_map.keys())
            ],
            "removed": [
                {"identity": key, "label": _asset_label(base_asset_map[key])}
                for key in sorted(base_asset_map.keys() - next_asset_map.keys())
            ],
        },
        "services": {
            "added": [
                service_payload(key, next_services[key])
                for key in sorted(next_services.keys() - base_services.keys())
            ],
            "removed": [
                service_payload(key, base_services[key])
                for key in sorted(base_services.keys() - next_services.keys())
            ],
        },
        "findings": {
            "added": [
                finding_payload(key, next_findings[key])
                for key in sorted(next_findings.keys() - base_findings.keys())
            ],
            "removed": [
                finding_payload(key, base_findings[key])
                for key in sorted(base_findings.keys() - next_findings.keys())
            ],
        },
    }
