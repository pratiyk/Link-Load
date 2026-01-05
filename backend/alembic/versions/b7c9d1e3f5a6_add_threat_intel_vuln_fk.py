"""Add vulnerability_id to threat_intel_data

Revision ID: b7c9d1e3f5a6
Revises: a6b8c9d0e1f2
Create Date: 2026-01-03 18:20:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b7c9d1e3f5a6"
down_revision: Union[str, None] = "a6b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "threat_intel_data",
        sa.Column(
            "vulnerability_id",
            sa.Integer(),
            sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("threat_intel_data", "vulnerability_id")
