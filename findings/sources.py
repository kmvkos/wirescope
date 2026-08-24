"""Load normalized inputs for the findings engine.

The engine never reads tool stdout. It consumes protocol_observations,
inventory services, and stored passive-result artifacts.
"""

from datetime import datetime

from findings.models import EvaluationContext
from inventory.service import InventoryService
from jobs.errors import JobExecutionError
from jobs.models import ArtifactRecord, RetentionClass
from persistence.database import Database
from persistence.models import ArtifactModel, utc_now
from protocol_audits.store import ProtocolObservationStore
from sqlalchemy import select
from storage.evidence import EvidenceStore


def load_evaluation_context(
    *,
    audit_id: str,
    database: Database,
    inventory: InventoryService,
    observations: ProtocolObservationStore,
    evidence_store: EvidenceStore | None,
    evaluated_at: datetime | None = None,
) -> EvaluationContext:
    assets = inventory.list_assets(
        audit_id=audit_id,
        limit=10_000,
        offset=0,
        include_services=False,
    ).items
    services = inventory.list_services(
        audit_id=audit_id,
        limit=10_000,
        offset=0,
    ).items
    records = observations.all_for_audit(audit_id)
    passive_result = None
    passive_artifact_id = None
    if evidence_store is not None:
        artifact = _latest_passive_artifact(database, audit_id)
        if artifact is not None:
            passive_artifact_id = artifact.id
            try:
                passive_result = evidence_store.read_json(artifact)
            except JobExecutionError:
                passive_result = None
    return EvaluationContext(
        audit_id=audit_id,
        observations=records,
        services=services,
        assets=assets,
        passive_result=passive_result,
        passive_artifact_id=passive_artifact_id,
        evaluated_at=evaluated_at or utc_now(),
    )


def _latest_passive_artifact(
    database: Database,
    audit_id: str,
) -> ArtifactRecord | None:
    with database.session() as session:
        model = session.scalar(
            select(ArtifactModel)
            .where(
                ArtifactModel.audit_id == audit_id,
                ArtifactModel.artifact_type == "passive_result",
            )
            .order_by(ArtifactModel.created_at.desc())
            .limit(1)
        )
        if model is None:
            return None
        return ArtifactRecord(
            id=model.id,
            audit_id=model.audit_id,
            job_id=model.job_id,
            artifact_type=model.artifact_type,
            relative_path=model.relative_path,
            content_type=model.content_type,
            size=model.size,
            sha256=model.sha256,
            created_at=model.created_at,
            retention_class=RetentionClass(model.retention_class),
            schema_name=model.schema_name,
            schema_version=model.schema_version,
        )
