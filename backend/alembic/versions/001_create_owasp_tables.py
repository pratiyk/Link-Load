"""Create OWASP scanning tables

Revision ID: 001_create_owasp_tables
Revises: 
Create Date: 2025-10-23 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from datetime import datetime

# revision identifiers, used by Alembic.
revision = '001_create_owasp_tables'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create owasp_scans table
    op.create_table(
        'owasp_scans',
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('target_url', sa.String(2048), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='pending', index=True),
        sa.Column('progress', sa.Integer, server_default='0'),
        sa.Column('current_stage', sa.String(255), server_default='Initializing'),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scan_types', postgresql.JSONB, server_default='[]'),
        sa.Column('options', postgresql.JSONB, server_default='{}'),
        sa.Column('risk_score', sa.Float, nullable=True),
        sa.Column('risk_level', sa.String(50), nullable=True),
        sa.Column('ai_analysis', postgresql.JSONB, nullable=True),
        sa.Column('mitre_mapping', postgresql.JSONB, nullable=True),
        sa.Column('remediation_strategies', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    
    # Create indexes on owasp_scans
    op.create_index('idx_owasp_scans_user_id', 'owasp_scans', ['user_id'])
    op.create_index('idx_owasp_scans_status', 'owasp_scans', ['status'])
    op.create_index('idx_owasp_scans_created_at', 'owasp_scans', ['created_at'])
    op.create_index('idx_owasp_scans_user_created', 'owasp_scans', ['user_id', 'created_at'])
    
    # Create owasp_vulnerabilities table
    op.create_table(
        'owasp_vulnerabilities',
        sa.Column('vulnerability_id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('title', sa.String(512), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('severity', sa.String(50), nullable=False, index=True),
        sa.Column('cvss_score', sa.Float, nullable=True),
        sa.Column('location', sa.String(2048), nullable=True),
        sa.Column('recommendation', sa.Text, nullable=True),
        sa.Column('mitre_techniques', postgresql.JSONB, server_default='[]'),
        sa.Column('scanner_source', sa.String(100), nullable=True),
        sa.Column('scanner_id', sa.String(256), nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(['scan_id'], ['owasp_scans.scan_id'], ondelete='CASCADE'),
    )
    
    # Create indexes on owasp_vulnerabilities
    op.create_index('idx_owasp_vulnerabilities_scan_id', 'owasp_vulnerabilities', ['scan_id'])
    op.create_index('idx_owasp_vulnerabilities_severity', 'owasp_vulnerabilities', ['severity'])
    op.create_index('idx_owasp_vulnerabilities_scan_severity', 'owasp_vulnerabilities', ['scan_id', 'severity'])
    
    # Create scan_audit_log table for tracking changes
    op.create_table(
        'scan_audit_log',
        sa.Column('audit_id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('old_status', sa.String(50), nullable=True),
        sa.Column('new_status', sa.String(50), nullable=True),
        sa.Column('details', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['scan_id'], ['owasp_scans.scan_id'], ondelete='CASCADE'),
    )
    
    # Create indexes on scan_audit_log
    op.create_index('idx_scan_audit_log_scan_id', 'scan_audit_log', ['scan_id'])
    op.create_index('idx_scan_audit_log_created_at', 'scan_audit_log', ['created_at'])


def downgrade():
    # Drop tables in reverse order (due to foreign key constraints)
    op.drop_table('scan_audit_log')
    op.drop_table('owasp_vulnerabilities')
    op.drop_table('owasp_scans')
