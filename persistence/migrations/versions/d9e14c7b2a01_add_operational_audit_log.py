"""add operational audit log

Revision ID: d9e14c7b2a01
Revises: b7d25e9a1c31
Create Date: 2026-08-25 00:20:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d9e14c7b2a01"
down_revision: Union[str, Sequence[str], None] = "b7d25e9a1c31"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operational_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=True),
        sa.Column("role", sa.String(length=16), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("method", sa.String(length=8), nullable=False),
        sa.Column("path", sa.String(length=512), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("audit_id", sa.String(length=36), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_operational_events_created",
        "operational_events",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_operational_events_action_created",
        "operational_events",
        ["action", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_operational_events_audit_created",
        "operational_events",
        ["audit_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_operational_events_actor_created",
        "operational_events",
        ["actor", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_operational_events_actor_created", table_name="operational_events")
    op.drop_index("ix_operational_events_audit_created", table_name="operational_events")
    op.drop_index("ix_operational_events_action_created", table_name="operational_events")
    op.drop_index("ix_operational_events_created", table_name="operational_events")
    op.drop_table("operational_events")
