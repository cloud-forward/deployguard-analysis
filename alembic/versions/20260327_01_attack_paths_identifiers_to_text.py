"""widen attack_paths canonical identifier columns to text

Revision ID: 20260327_01
Revises: None
Create Date: 2026-03-27 16:10:00

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260327_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "attack_paths",
        "path_id",
        existing_type=sa.String(length=255),
        type_=sa.Text(),
        existing_nullable=False,
    )
    op.alter_column(
        "attack_paths",
        "entry_node_id",
        existing_type=sa.String(length=255),
        type_=sa.Text(),
        existing_nullable=True,
    )
    op.alter_column(
        "attack_paths",
        "target_node_id",
        existing_type=sa.String(length=255),
        type_=sa.Text(),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "attack_paths",
        "target_node_id",
        existing_type=sa.Text(),
        type_=sa.String(length=255),
        existing_nullable=True,
    )
    op.alter_column(
        "attack_paths",
        "entry_node_id",
        existing_type=sa.Text(),
        type_=sa.String(length=255),
        existing_nullable=True,
    )
    op.alter_column(
        "attack_paths",
        "path_id",
        existing_type=sa.Text(),
        type_=sa.String(length=255),
        existing_nullable=False,
    )
