"""Shared helpers for declarative finding rules."""

from collections.abc import Iterable
from typing import Any

from findings.models import (
    EvaluationContext,
    FindingDraft,
    MAX_OBSERVATION_LINKS,
    NON_EVIDENCE_KINDS,
    Severity,
)
from inventory.models import ServiceRecord
from protocol_audits.models import ProtocolObservationRecord


def usable_observations(
    context: EvaluationContext,
    kinds: Iterable[str] | None = None,
) -> list[ProtocolObservationRecord]:
    allowed = set(kinds) if kinds is not None else None
    usable: list[ProtocolObservationRecord] = []
    for item in context.observations:
        if item.kind in NON_EVIDENCE_KINDS:
            continue
        if allowed is not None and item.kind not in allowed:
            continue
        usable.append(item)
    return usable


def service_map(context: EvaluationContext) -> dict[str, ServiceRecord]:
    return {item.id: item for item in context.services}


def observation_evidence(items: Iterable[ProtocolObservationRecord]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item.evidence_artifact_id and item.evidence_artifact_id not in seen:
            seen.add(item.evidence_artifact_id)
            ordered.append(item.evidence_artifact_id)
        if len(ordered) >= MAX_OBSERVATION_LINKS:
            break
    return ordered


def observation_ids(items: Iterable[ProtocolObservationRecord]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item.id not in seen:
            seen.add(item.id)
            ordered.append(item.id)
        if len(ordered) >= MAX_OBSERVATION_LINKS:
            break
    return ordered


def service_dedupe_key(observation: ProtocolObservationRecord) -> str:
    return f"{observation.asset_id}:{observation.service_id}"


def inventory_dedupe_key(service: ServiceRecord) -> str:
    return f"{service.asset_id}:{service.id}"


def grouped_by_service(
    items: Iterable[ProtocolObservationRecord],
) -> dict[tuple[str, str], list[ProtocolObservationRecord]]:
    groups: dict[tuple[str, str], list[ProtocolObservationRecord]] = {}
    for item in items:
        groups.setdefault((item.asset_id, item.service_id), []).append(item)
    return groups


def as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None and str(item)]
    return [str(value)]


def draft(
    *,
    rule_id: str,
    rule_version: str,
    family: str,
    title: str,
    severity: Severity,
    confidence,
    asset_id: str | None,
    service_id: str | None,
    description: str,
    rationale: str,
    recommendation: str,
    data: dict[str, Any],
    observations: Iterable[ProtocolObservationRecord] = (),
    evidence_artifact_ids: list[str] | None = None,
    dedupe_key: str,
) -> FindingDraft:
    linked = list(observations)
    evidence = list(evidence_artifact_ids or [])
    for item in observation_evidence(linked):
        if item not in evidence:
            evidence.append(item)
    return FindingDraft(
        rule_id=rule_id,
        rule_version=rule_version,
        family=family,
        title=title,
        severity=severity,
        confidence=confidence,
        asset_id=asset_id,
        service_id=service_id,
        description=description,
        rationale=rationale,
        recommendation=recommendation,
        data=data,
        observation_ids=observation_ids(linked),
        evidence_artifact_ids=evidence[:MAX_OBSERVATION_LINKS],
        dedupe_key=dedupe_key,
    )
