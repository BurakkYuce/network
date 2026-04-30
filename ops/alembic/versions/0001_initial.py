"""initial schema: device + state_snapshot

Revision ID: 0001
Revises:
Create Date: 2026-04-30 13:00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "device",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("role", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("tier", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("criticality", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("site", sa.String(64), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.UniqueConstraint("hostname", name="uq_device_hostname"),
    )
    op.create_index("ix_device_hostname", "device", ["hostname"])

    op.create_table(
        "state_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("state_json", sa.JSON(), nullable=False),
        sa.Column("raw_config_path", sa.String(512), nullable=True),
        sa.ForeignKeyConstraint(
            ["device_id"], ["device.id"], name="fk_snapshot_device"
        ),
    )
    op.create_index("ix_state_snapshot_device_id", "state_snapshot", ["device_id"])
    op.create_index("ix_state_snapshot_captured_at", "state_snapshot", ["captured_at"])


def downgrade() -> None:
    op.drop_index("ix_state_snapshot_captured_at", table_name="state_snapshot")
    op.drop_index("ix_state_snapshot_device_id", table_name="state_snapshot")
    op.drop_table("state_snapshot")
    op.drop_index("ix_device_hostname", table_name="device")
    op.drop_table("device")
