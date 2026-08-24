"""Idempotent persistence for findings and status audit-trail events."""

from typing import Any
import json
import uuid

from sqlalchemy import case, func, select

from engine.passive_models import ConfidenceLevel
from findings.models import (
    FINDING_SCHEMA_VERSION,
    FindingDraft,
    FindingRecord,
    FindingStateEventRecord,
    FindingStatus,
    MAX_FINDING_DATA_BYTES,
    MAX_OBSERVATION_LINKS,
    Severity,
)
from jobs.models import Page
from persistence.database import Database
from persistence.models import FindingModel, FindingStateEventModel, utc_now
from protocol_audits.store import MAX_LIST_ITEMS, MAX_STRING_VALUE


class FindingNotFound(LookupError):
    pass


class InvalidFindingState(ValueError):
    pass


_ALLOWED_TRANSITIONS = {
    FindingStatus.OPEN: {
        FindingStatus.SUPPRESSED,
        FindingStatus.ACCEPTED_RISK,
    },
    FindingStatus.SUPPRESSED: {
        FindingStatus.OPEN,
        FindingStatus.ACCEPTED_RISK,
    },
    FindingStatus.ACCEPTED_RISK: {
        FindingStatus.OPEN,
        FindingStatus.SUPPRESSED,
    },
}

_SEVERITY_ORDER = case(
    (FindingModel.severity == "critical", 0),
    (FindingModel.severity == "high", 1),
    (FindingModel.severity == "medium", 2),
    (FindingModel.severity == "low", 3),
    else_=4,
)


class FindingStore:
    def __init__(self, database: Database) -> None:
        self.database = database

    def upsert_evaluation(
        self,
        *,
        audit_id: str,
        drafts: list[FindingDraft],
    ) -> list[FindingRecord]:
        persisted: list[FindingRecord] = []
        with self.database.session() as session, session.begin():
            now = utc_now()
            for draft in drafts:
                data = _bound_data(draft.data)
                existing = session.scalar(
                    select(FindingModel).where(
                        FindingModel.audit_id == audit_id,
                        FindingModel.rule_id == draft.rule_id,
                        FindingModel.dedupe_key == draft.dedupe_key,
                    )
                )
                observation_ids = draft.observation_ids[:MAX_OBSERVATION_LINKS]
                evidence_ids = draft.evidence_artifact_ids[:MAX_OBSERVATION_LINKS]
                if existing is None:
                    existing = FindingModel(
                        id=str(uuid.uuid4()),
                        audit_id=audit_id,
                        asset_id=draft.asset_id,
                        service_id=draft.service_id,
                        rule_id=draft.rule_id,
                        rule_version=draft.rule_version,
                        schema_version=FINDING_SCHEMA_VERSION,
                        family=draft.family,
                        title=draft.title,
                        severity=draft.severity.value,
                        confidence=draft.confidence.value,
                        status=FindingStatus.OPEN.value,
                        description=draft.description,
                        rationale=draft.rationale,
                        recommendation=draft.recommendation,
                        data=data,
                        observation_ids=observation_ids,
                        evidence_artifact_ids=evidence_ids,
                        dedupe_key=draft.dedupe_key,
                        first_seen=now,
                        last_seen=now,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(existing)
                else:
                    existing.asset_id = draft.asset_id
                    existing.service_id = draft.service_id
                    existing.rule_version = draft.rule_version
                    existing.schema_version = FINDING_SCHEMA_VERSION
                    existing.family = draft.family
                    existing.title = draft.title
                    existing.severity = draft.severity.value
                    existing.confidence = draft.confidence.value
                    existing.description = draft.description
                    existing.rationale = draft.rationale
                    existing.recommendation = draft.recommendation
                    existing.data = data
                    existing.observation_ids = observation_ids
                    existing.evidence_artifact_ids = evidence_ids
                    existing.last_seen = now
                    existing.updated_at = now
                session.flush()
                persisted.append(_record(existing))
        return persisted

    def list_findings(
        self,
        *,
        audit_id: str,
        limit: int,
        offset: int,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
        asset_id: str | None = None,
        service_id: str | None = None,
        rule_id: str | None = None,
        family: str | None = None,
    ) -> Page[FindingRecord]:
        with self.database.session() as session:
            filters = [FindingModel.audit_id == audit_id]
            if severity is not None:
                filters.append(FindingModel.severity == severity.value)
            if status is not None:
                filters.append(FindingModel.status == status.value)
            if asset_id:
                filters.append(FindingModel.asset_id == asset_id)
            if service_id:
                filters.append(FindingModel.service_id == service_id)
            if rule_id:
                filters.append(FindingModel.rule_id == rule_id)
            if family:
                filters.append(FindingModel.family == family)
            total = session.scalar(
                select(func.count()).select_from(FindingModel).where(*filters)
            ) or 0
            rows = session.scalars(
                select(FindingModel)
                .where(*filters)
                .order_by(
                    _SEVERITY_ORDER,
                    FindingModel.rule_id,
                    FindingModel.id,
                )
                .limit(limit)
                .offset(offset)
            ).all()
            items = [_record(row) for row in rows]
        return Page[FindingRecord](
            items=items,
            limit=limit,
            offset=offset,
            total=total,
        )

    def get_finding(
        self,
        *,
        audit_id: str,
        finding_id: str,
        include_events: bool = True,
    ) -> FindingRecord:
        with self.database.session() as session:
            model = session.get(FindingModel, finding_id)
            if model is None or model.audit_id != audit_id:
                raise FindingNotFound(f"Finding not found: {finding_id}")
            events = []
            if include_events:
                rows = session.scalars(
                    select(FindingStateEventModel)
                    .where(FindingStateEventModel.finding_id == finding_id)
                    .order_by(FindingStateEventModel.id)
                ).all()
                events = [_event_record(row) for row in rows]
            return _record(model, events=events)

    def change_status(
        self,
        *,
        audit_id: str,
        finding_id: str,
        to_status: FindingStatus,
        actor: str,
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> FindingRecord:
        with self.database.session() as session, session.begin():
            model = session.get(FindingModel, finding_id)
            if model is None or model.audit_id != audit_id:
                raise FindingNotFound(f"Finding not found: {finding_id}")
            current = FindingStatus(model.status)
            allowed = _ALLOWED_TRANSITIONS[current]
            if to_status not in allowed:
                raise InvalidFindingState(
                    f"Cannot change finding status from {current.value} "
                    f"to {to_status.value}"
                )
            now = utc_now()
            event = FindingStateEventModel(
                finding_id=model.id,
                audit_id=audit_id,
                created_at=now,
                actor=actor,
                from_status=current.value,
                to_status=to_status.value,
                reason=reason,
                details=details or {},
            )
            model.status = to_status.value
            model.updated_at = now
            session.add(event)
            session.flush()
        return self.get_finding(audit_id=audit_id, finding_id=finding_id)

    def count(self, audit_id: str) -> int:
        with self.database.session() as session:
            return (
                session.scalar(
                    select(func.count())
                    .select_from(FindingModel)
                    .where(FindingModel.audit_id == audit_id)
                )
                or 0
            )

    def counts_by_severity(self, audit_id: str) -> dict[str, int]:
        with self.database.session() as session:
            rows = session.execute(
                select(FindingModel.severity, func.count())
                .where(FindingModel.audit_id == audit_id)
                .group_by(FindingModel.severity)
            ).all()
        counts = {item.value: 0 for item in Severity}
        for severity, total in rows:
            counts[str(severity)] = int(total)
        return counts


def _bound_data(data: dict[str, Any]) -> dict[str, Any]:
    bounded = _truncate(data)
    encoded = json.dumps(
        bounded,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    if len(encoded) <= MAX_FINDING_DATA_BYTES:
        return bounded
    return {
        "truncated": True,
        "keys": sorted(str(key) for key in data.keys())[:MAX_LIST_ITEMS],
        "original_bytes": len(encoded),
    }


def _truncate(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key)[:64]: _truncate(item)
            for key, item in list(value.items())[:MAX_LIST_ITEMS]
        }
    if isinstance(value, list):
        return [_truncate(item) for item in value[:MAX_LIST_ITEMS]]
    if isinstance(value, str) and len(value) > MAX_STRING_VALUE:
        return value[:MAX_STRING_VALUE]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)[:MAX_STRING_VALUE]


def _record(
    model: FindingModel,
    events: list[FindingStateEventRecord] | None = None,
) -> FindingRecord:
    return FindingRecord(
        id=model.id,
        audit_id=model.audit_id,
        asset_id=model.asset_id,
        service_id=model.service_id,
        rule_id=model.rule_id,
        rule_version=model.rule_version,
        schema_version=model.schema_version,
        family=model.family,
        title=model.title,
        severity=Severity(model.severity),
        confidence=ConfidenceLevel(model.confidence),
        status=FindingStatus(model.status),
        description=model.description,
        rationale=model.rationale,
        recommendation=model.recommendation,
        data=dict(model.data or {}),
        observation_ids=list(model.observation_ids or []),
        evidence_artifact_ids=list(model.evidence_artifact_ids or []),
        dedupe_key=model.dedupe_key,
        first_seen=model.first_seen,
        last_seen=model.last_seen,
        created_at=model.created_at,
        updated_at=model.updated_at,
        state_events=events or [],
    )


def _event_record(model: FindingStateEventModel) -> FindingStateEventRecord:
    return FindingStateEventRecord(
        id=model.id,
        finding_id=model.finding_id,
        audit_id=model.audit_id,
        created_at=model.created_at,
        actor=model.actor,
        from_status=FindingStatus(model.from_status),
        to_status=FindingStatus(model.to_status),
        reason=model.reason,
        details=dict(model.details or {}),
    )
