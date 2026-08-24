"""add reports history

Revision ID: a6c14f8d9e20
Revises: f5a91c3e7b04
Create Date: 2026-08-24 10:20:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a6c14f8d9e20"
down_revision: Union[str, Sequence[str], None] = "f5a91c3e7b04"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("audit_id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=True),
        sa.Column("schema_name", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=True),
        sa.Column("source_hash", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("json_artifact_id", sa.String(length=36), nullable=False),
        sa.Column("html_artifact_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["audit_id"],
            ["audits.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_reports_audit_generated",
        "reports",
        ["audit_id", "generated_at"],
        unique=False,
    )
    op.create_index(
        "ix_reports_job",
        "reports",
        ["job_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_reports_job", table_name="reports")
    op.drop_index("ix_reports_audit_generated", table_name="reports")
    op.drop_table("reports")
