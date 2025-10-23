"""Add batch processing tables

Revision ID: 94b3c7e2a1f9
Revises: previous_revision
Create Date: 2025-10-21 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '94b3c7e2a1f9'
down_revision = None  # Set this to your previous migration
branch_labels = None
depends_on = None

def upgrade():
    # Create batch_scans table
    op.create_table(
        'batch_scans',
        sa.Column('batch_id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('total_targets', sa.Integer, nullable=False),
        sa.Column('completed_targets', sa.Integer, nullable=False, server_default='0'),
        sa.Column('failed_targets', sa.Integer, nullable=False, server_default='0'),
        sa.Column('scan_config', sa.JSON, nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )

    # Create index on user_id
    op.create_index('idx_batch_scans_user_id', 'batch_scans', ['user_id'])
    op.create_index('idx_batch_scans_status', 'batch_scans', ['status'])

def downgrade():
    op.drop_table('batch_scans')