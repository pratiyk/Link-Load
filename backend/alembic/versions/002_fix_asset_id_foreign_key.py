"""Fix asset_id foreign key relationship

Revision ID: 002_fix_asset_id_foreign_key
Revises: 858291f951d8
Create Date: 2025-11-06 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_fix_asset_id_foreign_key'
down_revision = ('858291f951d8', '001_create_owasp_tables', '94b3c7e2a1f9')  # Merge heads
branch_labels = None
depends_on = None


def upgrade():
    """
    Fix the asset_id column in vulnerabilities table:
    1. Change type from String to Integer
    2. Add foreign key constraint to discovered_assets.id
    """
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if 'vulnerabilities' not in inspector.get_table_names():
        # Schema based on initial Alembic head does not include this table yet.
        return

    col_type = conn.execute(sa.text("""
        SELECT data_type
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'vulnerabilities'
          AND column_name = 'asset_id'
    """)).scalar()

    needs_conversion = col_type not in {'integer', 'bigint', 'smallint'}

    if needs_conversion:
        # First, clear any invalid data (asset_id that can't be converted to Integer)
        op.execute("""
            UPDATE vulnerabilities 
            SET asset_id = NULL 
            WHERE asset_id IS NOT NULL 
            AND asset_id !~ '^[0-9]+$'
        """)
        
        # Alter column type from String to Integer
        op.alter_column('vulnerabilities', 'asset_id',
                        existing_type=sa.String(),
                        type_=sa.Integer(),
                        existing_nullable=True,
                        postgresql_using='asset_id::integer')

    fk_names = {fk['name'] for fk in inspector.get_foreign_keys('vulnerabilities')}
    if 'fk_vulnerabilities_asset_id' not in fk_names:
        # Add foreign key constraint if missing
        op.create_foreign_key(
            'fk_vulnerabilities_asset_id',
            'vulnerabilities', 'discovered_assets',
            ['asset_id'], ['id'],
            ondelete='SET NULL'
        )

    existing_indexes = {idx['name'] for idx in inspector.get_indexes('vulnerabilities')}
    if 'ix_vulnerabilities_asset_id' not in existing_indexes:
        # Create index for better query performance
        op.create_index('ix_vulnerabilities_asset_id', 'vulnerabilities', ['asset_id'])


def downgrade():
    """Revert changes"""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if 'vulnerabilities' not in inspector.get_table_names():
        return
    
    # Drop index
    op.drop_index('ix_vulnerabilities_asset_id', table_name='vulnerabilities')
    
    # Drop foreign key constraint
    op.drop_constraint('fk_vulnerabilities_asset_id', 'vulnerabilities', type_='foreignkey')
    
    # Revert column type to String
    op.alter_column('vulnerabilities', 'asset_id',
                    existing_type=sa.Integer(),
                    type_=sa.String(),
                    existing_nullable=True,
                    postgresql_using='asset_id::text')
