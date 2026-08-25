"""Persist generated report history and generation metadata."""

from typing import Any
import uuid

from sqlalchemy import func, or_, select

from jobs.models import Page
from persistence.database import Database
from persistence.models import ArtifactModel, ReportModel, utc_now
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

    def delete(self, audit_id: str, report_id: str) -> tuple[ReportRecord, list[str]]:
        """Delete one generated report and unreferenced report artifacts.

        Audit/inventory/findings/job history is intentionally retained. Artifact
        metadata is removed only when no other report references the same
        artifact id. The caller may then remove the corresponding files from
        the evidence store using the returned ids.
        """
        with self.database.session() as session, session.begin():
            model = session.get(ReportModel, report_id)
            if model is None or model.audit_id != audit_id:
                raise ReportNotFound(f"Report not found: {report_id}")

            record = _record(model)
            artifact_ids = {
                value
                for value in (model.json_artifact_id, model.html_artifact_id)
                if value
            }
            session.delete(model)
            session.flush()

            deleted_artifact_ids: list[str] = []
            for artifact_id in sorted(artifact_ids):
                references = session.scalar(
                    select(func.count())
                    .select_from(ReportModel)
                    .where(
                        or_(
                            ReportModel.json_artifact_id == artifact_id,
                            ReportModel.html_artifact_id == artifact_id,
                        )
                    )
                ) or 0
                if references:
                    continue
                artifact = session.get(ArtifactModel, artifact_id)
                if artifact is None or artifact.audit_id != audit_id:
                    continue
                session.delete(artifact)
                deleted_artifact_ids.append(artifact_id)

        return record, deleted_artifact_ids


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
