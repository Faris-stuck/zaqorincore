"""v1.3.0 migration: add `soar_deliveries` table (ADR-008).

Per ADR-008 the SOAR worker writes one row per HTTP delivery attempt
so the operator can audit every webhook call. Schema mirrors the
SoarDelivery ORM model.

Columns:
    id             UUID PK
    alert_id       UUID NULL (no FK; alerts may be deleted)
    backend        String(32) NOT NULL
    status_code    Integer NOT NULL DEFAULT 0
    attempted_at   timestamptz NOT NULL DEFAULT now()
    duration_ms    Integer NOT NULL DEFAULT 0
    attempt        Integer NOT NULL DEFAULT 1
    error          String(2048) NULL
    dead_lettered  Boolean NOT NULL DEFAULT false
    payload_sha256 String(64) NULL

Indexes:
    ix_soar_deliveries_alert_id                 (alert_id)
    ix_soar_deliveries_backend_attempted_at     (backend, attempted_at)

Reversible: drops the table on downgrade.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision = "0003_soar_deliveries"
down_revision = "0002_auto_block"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "soar_deliveries",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
        ),
        sa.Column("alert_id", UUID(as_uuid=True), nullable=True),
        sa.Column("backend", sa.String(length=32), nullable=False),
        sa.Column(
            "status_code",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "attempted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "duration_ms",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "attempt",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("error", sa.String(length=2048), nullable=True),
        sa.Column(
            "dead_lettered",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("payload_sha256", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_soar_deliveries_alert_id",
        "soar_deliveries",
        ["alert_id"],
    )
    op.create_index(
        "ix_soar_deliveries_backend_attempted_at",
        "soar_deliveries",
        ["backend", "attempted_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_soar_deliveries_backend_attempted_at", table_name="soar_deliveries"
    )
    op.drop_index(
        "ix_soar_deliveries_alert_id", table_name="soar_deliveries"
    )
    op.drop_table("soar_deliveries")
