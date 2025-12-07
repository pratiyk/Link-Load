"""Add threat_intel column to owasp_scans

Revision ID: 004_add_threat_intel_column
Revises: 003_add_domain_verifications
Create Date: 2025-12-07 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '004_add_threat_intel_column'
down_revision = '003_add_domain_verifications'
branch_labels = None
depends_on = None


def upgrade():
    # Add threat_intel column to owasp_scans table
    op.add_column(
        'owasp_scans',
        sa.Column('threat_intel', postgresql.JSONB, nullable=True)
    )


def downgrade():
    op.drop_column('owasp_scans', 'threat_intel')
