"""Correlate observations and emit deterministic finding drafts."""

from findings.models import (
    CONFIDENCE_RANK,
    EvaluationContext,
    FindingDraft,
    SEVERITY_RANK,
    Severity,
)
from engine.passive_models import ConfidenceLevel
from findings.registry import RuleRegistry, default_registry


def evaluate_findings(
    context: EvaluationContext,
    registry: RuleRegistry | None = None,
) -> list[FindingDraft]:
    active = registry or default_registry()
    drafts: list[FindingDraft] = []
    for rule in active.rules:
        produced = rule.evaluate(context)
        drafts.extend(produced)
    return deduplicate_drafts(drafts)


def deduplicate_drafts(drafts: list[FindingDraft]) -> list[FindingDraft]:
    merged: dict[tuple[str, str], FindingDraft] = {}
    for draft in drafts:
        key = (draft.rule_id, draft.dedupe_key)
        existing = merged.get(key)
        if existing is None:
            merged[key] = draft
            continue
        merged[key] = _merge(existing, draft)
    return [
        merged[key]
        for key in sorted(
            merged,
            key=lambda item: (
                SEVERITY_RANK[merged[item].severity],
                merged[item].rule_id,
                merged[item].dedupe_key,
            ),
        )
    ]


def _merge(left: FindingDraft, right: FindingDraft) -> FindingDraft:
    observations = list(left.observation_ids)
    for item in right.observation_ids:
        if item not in observations:
            observations.append(item)
    evidence = list(left.evidence_artifact_ids)
    for item in right.evidence_artifact_ids:
        if item not in evidence:
            evidence.append(item)
    data = {**left.data, **right.data}
    if left.observation_ids or right.observation_ids:
        data["correlated_observation_count"] = len(observations)
    severity = (
        left.severity
        if SEVERITY_RANK[left.severity] <= SEVERITY_RANK[right.severity]
        else right.severity
    )
    confidence = (
        left.confidence
        if CONFIDENCE_RANK[left.confidence] <= CONFIDENCE_RANK[right.confidence]
        else right.confidence
    )
    return left.model_copy(
        update={
            "severity": Severity(severity),
            "confidence": ConfidenceLevel(confidence),
            "observation_ids": observations,
            "evidence_artifact_ids": evidence,
            "data": data,
            "rationale": left.rationale
            if left.rationale == right.rationale
            else f"{left.rationale} {right.rationale}",
        }
    )
