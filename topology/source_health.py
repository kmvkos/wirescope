"""Report persisted topology enrichment artifacts that were silently skipped.

SNMP and route-trace decorators intentionally tolerate a damaged historical
artifact so one bad file cannot take down the whole topology view.  This layer
makes that tolerance visible: the map remains usable, but is marked partial and
identifies the omitted artifact without exposing exception text or file paths.
"""

from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy import select

from persistence.models import ArtifactModel, JobModel


_RULES = {
    "route_trace_result": {
        "component": "route-trace",
        "limit": 8,
        "used_block": "upstream",
        "deduplicate_target": False,
    },
    "snmp_topology_result": {
        "component": "snmp-topology",
        "limit": 32,
        "used_block": "snmp_topology",
        "deduplicate_target": True,
    },
}


def _append_unique(values: list[Any], value: Any) -> None:
    if value not in values:
        values.append(value)


def _candidate_rows(services, audit_id: str, artifact_type: str, *, limit: int):
    with services.database.session() as session:
        return session.execute(
            select(ArtifactModel, JobModel)
            .outerjoin(JobModel, ArtifactModel.job_id == JobModel.id)
            .where(
                ArtifactModel.audit_id == audit_id,
                ArtifactModel.artifact_type == artifact_type,
            )
            .order_by(ArtifactModel.created_at.desc())
            .limit(limit)
        ).all()


def _job_target(job: JobModel | None) -> str:
    if job is None:
        return ""
    parameters = dict(job.parameters or {})
    return str(parameters.get("target") or job.target or "").strip()


def _candidate_artifacts(
    services,
    audit_id: str,
    artifact_type: str,
    *,
    limit: int,
    deduplicate_target: bool,
) -> list[ArtifactModel]:
    rows = _candidate_rows(services, audit_id, artifact_type, limit=limit)
    if not deduplicate_target:
        return [artifact for artifact, _job in rows]

    result: list[ArtifactModel] = []
    seen_targets: set[str] = set()
    for artifact, job in rows:
        target = _job_target(job)
        if target:
            if target in seen_targets:
                continue
            seen_targets.add(target)
        result.append(artifact)
    return result


def _used_artifact_ids(topology: dict[str, Any], block: str) -> set[str]:
    payload = topology.get(block) or {}
    return {str(value) for value in payload.get("artifact_ids") or [] if value}


def _error_key(error: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(error.get("audit_id") or ""),
        str(error.get("component") or ""),
        str(error.get("artifact_id") or ""),
    )


def decorate_source_health(
    services,
    topology: dict[str, Any],
    *,
    audit_ids: Iterable[str],
) -> dict[str, Any]:
    """Mark a topology partial when retained enrichment artifacts were omitted."""
    errors = list(topology.get("source_errors") or [])
    existing = {_error_key(error) for error in errors if isinstance(error, dict)}
    new_errors = 0

    for audit_id in dict.fromkeys(str(value) for value in audit_ids if value):
        for artifact_type, rule in _RULES.items():
            used = _used_artifact_ids(topology, str(rule["used_block"]))
            deduplicate_target = bool(rule["deduplicate_target"])
            candidates = _candidate_artifacts(
                services,
                audit_id,
                artifact_type,
                limit=int(rule["limit"]),
                deduplicate_target=deduplicate_target,
            )
            for artifact in candidates:
                if artifact.id in used:
                    continue
                if deduplicate_target and artifact.job_id is None:
                    # Old/manual SNMP artifacts can lack a job target. Without
                    # that target we cannot know whether an unused row is a bad
                    # source or merely an older duplicate of a newer device
                    # snapshot, so do not manufacture an error.
                    continue
                error = {
                    "audit_id": audit_id,
                    "artifact_id": artifact.id,
                    "artifact_type": artifact_type,
                    "component": str(rule["component"]),
                    "code": "artifact_unavailable",
                    "schema_name": artifact.schema_name,
                    "schema_version": artifact.schema_version,
                }
                key = _error_key(error)
                if key in existing:
                    continue
                existing.add(key)
                errors.append(error)
                new_errors += 1

    if errors:
        topology["partial"] = True
        topology["source_errors"] = errors
        summary = topology.setdefault("summary", {})
        summary["source_errors"] = len(errors)
    else:
        topology.setdefault("partial", False)
        topology.setdefault("source_errors", [])

    if new_errors:
        warning = (
            f"Topology неполная: {new_errors} сохранённых SNMP/route-trace artifacts "
            "не вошли в карту. Подробности доступны в source_errors."
        )
        warnings = topology.setdefault("warnings", [])
        _append_unique(warnings, warning)
    return topology
