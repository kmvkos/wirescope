"""add findings and finding state events

Revision ID: f5a91c3e7b04
Revises: c4a8e91b6d03
Create Date: 2026-08-24 09:50:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f5a91c3e7b04"
down_revision: Union[str, Sequence[str], None] = "c4a8e91b6d03"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("audit_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("service_id", sa.String(length=36), nullable=True),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=16), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("family", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("observation_ids", sa.JSON(), nullable=False),
        sa.Column("evidence_artifact_ids", sa.JSON(), nullable=False),
        sa.Column("dedupe_key", sa.String(length=128), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="ck_findings_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('confirmed','high','medium','low',"
            "'hint','unknown')",
            name="ck_findings_confidence",
        ),
        sa.CheckConstraint(
            "status IN ('open','suppressed','accepted_risk')",
            name="ck_findings_status",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["audit_id"],
            ["audits.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["service_id"],
            ["services.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "audit_id",
            "rule_id",
            "dedupe_key",
            name="uq_findings_identity",
        ),
    )
    op.create_index(
        "ix_findings_audit_asset",
        "findings",
        ["audit_id", "asset_id"],
        unique=False,
    )
    op.create_index(
        "ix_findings_audit_family",
        "findings",
        ["audit_id", "family"],
        unique=False,
    )
    op.create_index(
        "ix_findings_audit_severity",
        "findings",
        ["audit_id", "severity"],
        unique=False,
    )
    op.create_index(
        "ix_findings_audit_status",
        "findings",
        ["audit_id", "status"],
        unique=False,
    )
    op.create_table(
        "finding_state_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("audit_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("from_status", sa.String(length=32), nullable=False),
        sa.Column("to_status", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=512), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.CheckConstraint(
            "from_status IN ('open','suppressed','accepted_risk')",
            name="ck_finding_state_events_from_status",
        ),
        sa.CheckConstraint(
            "to_status IN ('open','suppressed','accepted_risk')",
            name="ck_finding_state_events_to_status",
        ),
        sa.ForeignKeyConstraint(
            ["audit_id"],
            ["audits.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_finding_state_events_audit",
        "finding_state_events",
        ["audit_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_finding_state_events_finding",
        "finding_state_events",
        ["finding_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_finding_state_events_finding",
        table_name="finding_state_events",
    )
    op.drop_index(
        "ix_finding_state_events_audit",
        table_name="finding_state_events",
    )
    op.drop_table("finding_state_events")
    op.drop_index("ix_findings_audit_status", table_name="findings")
    op.drop_index("ix_findings_audit_severity", table_name="findings")
    op.drop_index("ix_findings_audit_family", table_name="findings")
    op.drop_index("ix_findings_audit_asset", table_name="findings")
    op.drop_table("findings")
