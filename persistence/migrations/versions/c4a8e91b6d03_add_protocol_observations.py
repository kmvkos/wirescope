"""add protocol observations

Revision ID: c4a8e91b6d03
Revises: 6ed8035c74fb
Create Date: 2026-08-23 23:30:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c4a8e91b6d03"
down_revision: Union[str, Sequence[str], None] = "6ed8035c74fb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "protocol_observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("audit_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("service_id", sa.String(length=36), nullable=False),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("module", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("dedupe_key", sa.String(length=64), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("evidence_artifact_id", sa.String(length=36), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "confidence IN ('confirmed','high','medium','low',"
            "'hint','unknown')",
            name="ck_protocol_observations_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["audit_id"],
            ["audits.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["service_id"],
            ["services.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "audit_id",
            "asset_id",
            "service_id",
            "module",
            "kind",
            "dedupe_key",
            name="uq_protocol_observations_identity",
        ),
    )
    op.create_index(
        "ix_protocol_observations_audit_asset",
        "protocol_observations",
        ["audit_id", "asset_id"],
        unique=False,
    )
    op.create_index(
        "ix_protocol_observations_audit_module",
        "protocol_observations",
        ["audit_id", "module", "protocol"],
        unique=False,
    )
    op.create_index(
        "ix_protocol_observations_audit_service",
        "protocol_observations",
        ["audit_id", "service_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_protocol_observations_audit_service",
        table_name="protocol_observations",
    )
    op.drop_index(
        "ix_protocol_observations_audit_module",
        table_name="protocol_observations",
    )
    op.drop_index(
        "ix_protocol_observations_audit_asset",
        table_name="protocol_observations",
    )
    op.drop_table("protocol_observations")
