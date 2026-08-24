"""Idempotent persistence for normalized protocol observations."""

from typing import Any
import json
import uuid

from sqlalchemy import func, select

from engine.passive_models import ConfidenceLevel
from jobs.models import Page
from persistence.database import Database
from persistence.models import ProtocolObservationModel, utc_now
from protocol_audits.models import (
    MAX_LIST_ITEMS,
    MAX_OBSERVATION_DATA_BYTES,
    MAX_STRING_VALUE,
    ObservationDraft,
    ProtocolObservationRecord,
)


class ProtocolObservationStore:
    def __init__(self, database: Database) -> None:
        self.database = database

    def upsert_many(
        self,
        *,
        audit_id: str,
        asset_id: str,
        service_id: str,
        protocol: str,
        module: str,
        drafts: list[ObservationDraft],
        evidence_artifact_id: str | None,
    ) -> list[ProtocolObservationRecord]:
        persisted: list[ProtocolObservationRecord] = []
        with self.database.session() as session, session.begin():
            for draft in drafts:
                data = bound_observation_data(draft.data)
                existing = session.scalar(
                    select(ProtocolObservationModel).where(
                        ProtocolObservationModel.audit_id == audit_id,
                        ProtocolObservationModel.asset_id == asset_id,
                        ProtocolObservationModel.service_id == service_id,
                        ProtocolObservationModel.module == module,
                        ProtocolObservationModel.kind == draft.kind,
                        ProtocolObservationModel.dedupe_key == draft.dedupe_key,
                    )
                )
                now = utc_now()
                if existing is None:
                    existing = ProtocolObservationModel(
                        id=str(uuid.uuid4()),
                        audit_id=audit_id,
                        asset_id=asset_id,
                        service_id=service_id,
                        protocol=protocol,
                        module=module,
                        kind=draft.kind,
                        dedupe_key=draft.dedupe_key,
                        data=data,
                        confidence=draft.confidence.value,
                        source=draft.source,
                        evidence_artifact_id=evidence_artifact_id,
                        first_seen=now,
                        last_seen=now,
                    )
                    session.add(existing)
                else:
                    existing.data = data
                    existing.confidence = draft.confidence.value
                    existing.source = draft.source
                    existing.evidence_artifact_id = evidence_artifact_id
                    existing.last_seen = now
                    existing.protocol = protocol
                session.flush()
                persisted.append(_record(existing))
        return persisted

    def list_observations(
        self,
        *,
        audit_id: str,
        limit: int,
        offset: int,
        asset_id: str | None = None,
        protocol: str | None = None,
        module: str | None = None,
        kind: str | None = None,
        service_id: str | None = None,
    ) -> Page[ProtocolObservationRecord]:
        with self.database.session() as session:
            filters = [ProtocolObservationModel.audit_id == audit_id]
            if asset_id:
                filters.append(ProtocolObservationModel.asset_id == asset_id)
            if protocol:
                filters.append(
                    ProtocolObservationModel.protocol == protocol.lower()
                )
            if module:
                filters.append(ProtocolObservationModel.module == module.lower())
            if kind:
                filters.append(ProtocolObservationModel.kind == kind)
            if service_id:
                filters.append(ProtocolObservationModel.service_id == service_id)
            total = session.scalar(
                select(func.count())
                .select_from(ProtocolObservationModel)
                .where(*filters)
            ) or 0
            rows = session.scalars(
                select(ProtocolObservationModel)
                .where(*filters)
                .order_by(
                    ProtocolObservationModel.module,
                    ProtocolObservationModel.kind,
                    ProtocolObservationModel.id,
                )
                .limit(limit)
                .offset(offset)
            ).all()
            items = [_record(row) for row in rows]
        return Page[ProtocolObservationRecord](
            items=items,
            limit=limit,
            offset=offset,
            total=total,
        )

    def all_for_audit(self, audit_id: str) -> list[ProtocolObservationRecord]:
        with self.database.session() as session:
            rows = session.scalars(
                select(ProtocolObservationModel)
                .where(ProtocolObservationModel.audit_id == audit_id)
                .order_by(
                    ProtocolObservationModel.module,
                    ProtocolObservationModel.kind,
                    ProtocolObservationModel.id,
                )
            ).all()
            return [_record(row) for row in rows]

    def count(self, audit_id: str) -> int:
        with self.database.session() as session:
            return (
                session.scalar(
                    select(func.count())
                    .select_from(ProtocolObservationModel)
                    .where(ProtocolObservationModel.audit_id == audit_id)
                )
                or 0
            )


def bound_observation_data(data: dict[str, Any]) -> dict[str, Any]:
    bounded = _truncate(data)
    encoded = _encode(bounded)
    if len(encoded) <= MAX_OBSERVATION_DATA_BYTES:
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


def _encode(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode("utf-8")


def _record(model: ProtocolObservationModel) -> ProtocolObservationRecord:
    return ProtocolObservationRecord(
        id=model.id,
        audit_id=model.audit_id,
        asset_id=model.asset_id,
        service_id=model.service_id,
        protocol=model.protocol,
        module=model.module,
        kind=model.kind,
        data=dict(model.data or {}),
        confidence=ConfidenceLevel(model.confidence),
        source=model.source,
        evidence_artifact_id=model.evidence_artifact_id,
        first_seen=model.first_seen,
        last_seen=model.last_seen,
    )
