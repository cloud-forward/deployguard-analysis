"""add risk_score and raw_final_risk columns to attack_paths

Revision ID: 20260331_01
Revises: 20260327_01
Create Date: 2026-03-31 00:00:00

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260331_01"
down_revision = "20260327_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "attack_paths",
        sa.Column("risk_score", sa.Float(), nullable=True),
    )
    op.add_column(
        "attack_paths",
        sa.Column("raw_final_risk", sa.Float(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("attack_paths", "raw_final_risk")
    op.drop_column("attack_paths", "risk_score")
