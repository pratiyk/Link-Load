"""Add domain_verifications table and executive_summary column

Revision ID: 003_add_domain_verifications
Revises: 002_fix_asset_id_foreign_key
Create Date: 2025-11-30

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '003_add_domain_verifications'
down_revision = '002_fix_asset_id_foreign_key'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create domain_verifications table
    op.create_table(
        'domain_verifications',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('domain', sa.String(255), nullable=False),
        sa.Column('host_label', sa.String(512), nullable=False),
        sa.Column('token', sa.String(128), nullable=False),
        sa.Column('status', sa.String(32), nullable=False, server_default='pending'),
        sa.Column('verification_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('user_id', 'domain', name='uq_domain_verification_user_domain')
    )
    op.create_index('ix_domain_verifications_user_id', 'domain_verifications', ['user_id'])

    # Add executive_summary column to owasp_scans if it doesn't exist
    # Using a try/except pattern via raw SQL to handle if column already exists
    op.execute("""
        DO $$ 
        BEGIN 
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'owasp_scans' AND column_name = 'executive_summary'
            ) THEN
                ALTER TABLE owasp_scans ADD COLUMN executive_summary TEXT;
            END IF;
        END $$;
    """)


def downgrade() -> None:
    # Drop executive_summary column from owasp_scans
    op.execute("""
        DO $$ 
        BEGIN 
            IF EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'owasp_scans' AND column_name = 'executive_summary'
            ) THEN
                ALTER TABLE owasp_scans DROP COLUMN executive_summary;
            END IF;
        END $$;
    """)

    # Drop domain_verifications table
    op.drop_index('ix_domain_verifications_user_id', table_name='domain_verifications')
    op.drop_table('domain_verifications')
