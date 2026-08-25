"""Historical topology comparison with source-completeness metadata."""

from __future__ import annotations

from typing import Any

from topology.compare import compare_topologies


def compare_topology_history(
    *,
    baseline: dict[str, Any],
    current: dict[str, Any],
    baseline_audit_id: str | None = None,
    current_audit_id: str | None = None,
) -> dict[str, Any]:
    result = compare_topologies(
        baseline=baseline,
        current=current,
        baseline_audit_id=baseline_audit_id,
        current_audit_id=current_audit_id,
    )
    warnings = result.setdefault("warnings", [])
    partial = False

    for name, topology, label in (
        ("baseline", baseline, "Базовая topology"),
        ("current", current, "Текущая topology"),
    ):
        source_errors = [
            item
            for item in topology.get("source_errors") or []
            if isinstance(item, dict)
        ]
        side_partial = bool(topology.get("partial") or source_errors)
        result.setdefault(name, {})["partial"] = side_partial
        result[name]["source_error_count"] = len(source_errors)
        if side_partial:
            partial = True
            warning = (
                f"{label} неполная: часть persisted evidence не вошла в карту; "
                "historical diff может не отражать некоторые изменения."
            )
            if warning not in warnings:
                warnings.append(warning)

    result["partial"] = partial
    result.setdefault("summary", {})["baseline_source_errors"] = result["baseline"]["source_error_count"]
    result["summary"]["current_source_errors"] = result["current"]["source_error_count"]
    return result
