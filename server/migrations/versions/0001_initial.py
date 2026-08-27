"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-28 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_version", sa.String(length=32), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column(
            "meta",
            postgresql.JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.create_index("idx_hosts_last_seen", "hosts", ["last_seen_at"], unique=False)

    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("schema", sa.String(length=16), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("raw", sa.Text, nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.create_index("idx_events_host_time", "events", ["host_id", "occurred_at"], unique=False)
    op.create_index("idx_events_received", "events", ["received_at"], unique=False)
    op.create_index("idx_events_source", "events", ["source"], unique=False)

    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("detector", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("summary", sa.String(length=512), nullable=False),
        sa.Column(
            "detail",
            postgresql.JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_alerts_host_time", "alerts", ["host_id", "created_at"], unique=False)

    op.create_table(
        "actions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("ttl_sec", sa.Integer, nullable=True),
        sa.Column(
            "status",
            sa.String(length=16),
            server_default="pending",
            nullable=False,
        ),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("idx_actions_host_time", "actions", ["host_id", "created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("idx_actions_host_time", table_name="actions")
    op.drop_table("actions")
    op.drop_index("idx_alerts_host_time", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index("idx_events_source", table_name="events")
    op.drop_index("idx_events_received", table_name="events")
    op.drop_index("idx_events_host_time", table_name="events")
    op.drop_table("events")
    op.drop_index("idx_hosts_last_seen", table_name="hosts")
    op.drop_table("hosts")
