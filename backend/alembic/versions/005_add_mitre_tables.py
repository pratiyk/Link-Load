"""Add MITRE ATT&CK tables

Revision ID: 005_add_mitre_tables
Revises: 004_add_threat_intel_column
Create Date: 2026-01-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "005_add_mitre_tables"
down_revision: Union[str, None] = "004_add_threat_intel_column"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mitre_tactics",
        sa.Column("tactic_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("url", sa.String(length=512), nullable=True),
        sa.Column("matrix", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("tactic_id")
    )
    op.create_index("ix_mitre_tactics_name", "mitre_tactics", ["name"])
    op.create_index("ix_mitre_tactics_matrix", "mitre_tactics", ["matrix"])

    op.create_table(
        "mitre_techniques",
        sa.Column("technique_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("detection", sa.Text(), nullable=True),
        sa.Column("url", sa.String(length=512), nullable=True),
        sa.Column("data_sources", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("platforms", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("permissions_required", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("technique_id")
    )
    op.create_index("ix_mitre_techniques_name", "mitre_techniques", ["name"])

    op.create_table(
        "capec_patterns",
        sa.Column("pattern_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("likelihood", sa.String(length=64), nullable=True),
        sa.Column("typical_likelihood", sa.String(length=64), nullable=True),
        sa.Column("typical_severity", sa.String(length=64), nullable=True),
        sa.Column("prerequisites", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("mitigations", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("mitre_technique_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("pattern_id")
    )

    op.create_table(
        "mitre_sub_techniques",
        sa.Column("sub_technique_id", sa.String(length=64), nullable=False),
        sa.Column("parent_technique_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("detection", sa.Text(), nullable=True),
        sa.Column("url", sa.String(length=512), nullable=True),
        sa.Column("data_sources", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["parent_technique_id"], ["mitre_techniques.technique_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("sub_technique_id")
    )
    op.create_index(
        "ix_mitre_sub_techniques_parent",
        "mitre_sub_techniques",
        ["parent_technique_id"]
    )

    op.create_table(
        "technique_tactic_association",
        sa.Column("technique_id", sa.String(length=64), nullable=False),
        sa.Column("tactic_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["tactic_id"], ["mitre_tactics.tactic_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["technique_id"], ["mitre_techniques.technique_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("technique_id", "tactic_id")
    )

    op.create_table(
        "technique_capec_association",
        sa.Column("technique_id", sa.String(length=64), nullable=False),
        sa.Column("pattern_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["pattern_id"], ["capec_patterns.pattern_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["technique_id"], ["mitre_techniques.technique_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("technique_id", "pattern_id")
    )

    op.create_table(
        "vulnerability_technique_association",
        sa.Column("vulnerability_id", sa.Integer(), nullable=False),
        sa.Column("technique_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["technique_id"], ["mitre_techniques.technique_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerabilities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("vulnerability_id", "technique_id")
    )
    op.create_index(
        "ix_vulnerability_technique_association_technique",
        "vulnerability_technique_association",
        ["technique_id"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_vulnerability_technique_association_technique",
        table_name="vulnerability_technique_association"
    )
    op.drop_table("vulnerability_technique_association")

    op.drop_table("technique_capec_association")
    op.drop_table("technique_tactic_association")

    op.drop_index("ix_mitre_sub_techniques_parent", table_name="mitre_sub_techniques")
    op.drop_table("mitre_sub_techniques")

    op.drop_table("capec_patterns")

    op.drop_index("ix_mitre_techniques_name", table_name="mitre_techniques")
    op.drop_table("mitre_techniques")

    op.drop_index("ix_mitre_tactics_matrix", table_name="mitre_tactics")
    op.drop_index("ix_mitre_tactics_name", table_name="mitre_tactics")
    op.drop_table("mitre_tactics")