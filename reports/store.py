"""Persist generated report history and generation metadata."""

from typing import Any
import uuid

from sqlalchemy import func, select

from jobs.models import Page
from persistence.database import Database
from persistence.models import ReportModel, utc_now
from reports.models import REPORT_SCHEMA, REPORT_SCHEMA_VERSION, ReportRecord


class ReportNotFound(LookupError):
    pass


class ReportStore:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(
        self,
        *,
        audit_id: str,
        job_id: str | None,
        actor: str | None,
        source_hash: str,
        summary: dict[str, Any],
        json_artifact_id: str,
        html_artifact_id: str,
        report_id: str | None = None,
        generated_at=None,
    ) -> ReportRecord:
        now = generated_at or utc_now()
        model = ReportModel(
            id=report_id or str(uuid.uuid4()),
            audit_id=audit_id,
            job_id=job_id,
            schema_name=REPORT_SCHEMA,
            schema_version=REPORT_SCHEMA_VERSION,
            generated_at=now,
            actor=actor,
            source_hash=source_hash,
            summary=summary,
            json_artifact_id=json_artifact_id,
            html_artifact_id=html_artifact_id,
            created_at=now,
        )
        with self.database.session() as session, session.begin():
            session.add(model)
        return _record(model)

    def get(self, audit_id: str, report_id: str) -> ReportRecord:
        with self.database.session() as session:
            model = session.get(ReportModel, report_id)
            if model is None or model.audit_id != audit_id:
                raise ReportNotFound(f"Report not found: {report_id}")
            return _record(model)

    def list_reports(
        self,
        *,
        audit_id: str,
        limit: int,
        offset: int,
    ) -> Page[ReportRecord]:
        with self.database.session() as session:
            filters = [ReportModel.audit_id == audit_id]
            total = session.scalar(
                select(func.count()).select_from(ReportModel).where(*filters)
            ) or 0
            rows = session.scalars(
                select(ReportModel)
                .where(*filters)
                .order_by(ReportModel.generated_at.desc(), ReportModel.id.desc())
                .limit(limit)
                .offset(offset)
            ).all()
        return Page[ReportRecord](
            items=[_record(row) for row in rows],
            limit=limit,
            offset=offset,
            total=total,
        )


def _record(model: ReportModel) -> ReportRecord:
    return ReportRecord(
        id=model.id,
        audit_id=model.audit_id,
        job_id=model.job_id,
        schema_name=model.schema_name,
        schema_version=model.schema_version,
        generated_at=model.generated_at,
        actor=model.actor,
        source_hash=model.source_hash,
        summary=dict(model.summary or {}),
        json_artifact_id=model.json_artifact_id,
        html_artifact_id=model.html_artifact_id,
        created_at=model.created_at,
    )
