"""Legacy batch processing table placeholder.

Revision ID: 94b3c7e2a1f9
Revises: cd3650f92a1d
Create Date: 2025-10-21 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '94b3c7e2a1f9'
down_revision = 'cd3650f92a1d'
branch_labels = None
depends_on = None


def upgrade():
    """Ensure legacy indexes exist without recreating tables."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if 'batch_scans' not in inspector.get_table_names():
        return

    existing_indexes = {idx['name'] for idx in inspector.get_indexes('batch_scans')}
    if 'idx_batch_scans_user_id' not in existing_indexes:
        op.create_index('idx_batch_scans_user_id', 'batch_scans', ['user_id'])
    if 'idx_batch_scans_status' not in existing_indexes:
        op.create_index('idx_batch_scans_status', 'batch_scans', ['status'])


def downgrade():
    """Drop indexes created in upgrade if they exist."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_indexes = set()
    if 'batch_scans' in inspector.get_table_names():
        existing_indexes = {idx['name'] for idx in inspector.get_indexes('batch_scans')}

    if 'idx_batch_scans_status' in existing_indexes:
        op.drop_index('idx_batch_scans_status', table_name='batch_scans')
    if 'idx_batch_scans_user_id' in existing_indexes:
        op.drop_index('idx_batch_scans_user_id', table_name='batch_scans')