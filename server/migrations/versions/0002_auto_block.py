"""Phase 4 migration: add per-host secret + auto_block flag.

Adds two columns to `hosts`:
  - `secret`     String(128) NULL
  - `auto_block` Boolean NOT NULL DEFAULT false

Reversible: drops both columns on downgrade.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0002_auto_block"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "hosts",
        sa.Column("secret", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "hosts",
        sa.Column(
            "auto_block",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("hosts", "auto_block")
    op.drop_column("hosts", "secret")
