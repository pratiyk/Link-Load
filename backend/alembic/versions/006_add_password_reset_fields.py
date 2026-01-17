"""add password reset fields

Revision ID: 006_add_password_reset_fields
Revises: 005_add_mitre_tables
Create Date: 2026-01-17

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '006_add_password_reset_fields'
down_revision = '005_add_mitre_tables'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add password reset fields to users table
    op.add_column('users', sa.Column('reset_token', sa.String(), nullable=True))
    op.add_column('users', sa.Column('reset_token_expires', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    # Remove password reset fields from users table
    op.drop_column('users', 'reset_token_expires')
    op.drop_column('users', 'reset_token')
