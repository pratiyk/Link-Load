"""Initial schema

Revision ID: cd3650f92a1d
Revises: 
Create Date: 2025-10-22 11:43:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from datetime import datetime

# revision identifiers, used by Alembic.
revision = 'cd3650f92a1d'
down_revision = None
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

    # Create indexes on batch_scans
    op.create_index('idx_batch_scans_user_id', 'batch_scans', ['user_id'])
    op.create_index('idx_batch_scans_status', 'batch_scans', ['status'])

    # Create security_scans table
    op.create_table(
        'security_scans',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('target_url', sa.String(), nullable=False),
        sa.Column('scan_types', sa.JSON()),
        sa.Column('status', sa.String(), server_default='pending'),
        sa.Column('started_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime()),
        sa.Column('duration', sa.Integer()),
        sa.Column('scan_config', sa.JSON()),
        sa.Column('progress', sa.JSON()),
        sa.Column('summary', sa.JSON()),
        sa.Column('errors', sa.JSON()),
        sa.Column('environment_info', sa.JSON())
    )

    # Create indexes on security_scans
    op.create_index('ix_security_scans_target_url', 'security_scans', ['target_url'])
    op.create_index('ix_security_scans_user_id', 'security_scans', ['user_id'])

    # Create vulnerability_findings table
    op.create_table(
        'vulnerability_findings',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('security_scans.id')),
        sa.Column('scanner', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String()),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('confidence', sa.String()),
        sa.Column('url', sa.String()),
        sa.Column('parameter', sa.String()),
        sa.Column('method', sa.String()),
        sa.Column('solution', sa.String()),
        sa.Column('references', sa.JSON()),
        sa.Column('evidence', sa.String()),
        sa.Column('payload', sa.String()),
        sa.Column('cwe_id', sa.String()),
        sa.Column('owasp_category', sa.String()),
        sa.Column('tags', sa.JSON()),
        sa.Column('attack_complexity', sa.String()),
        sa.Column('attack_vector', sa.String()),
        sa.Column('privileges_required', sa.String()),
        sa.Column('user_interaction', sa.String()),
        sa.Column('impact', sa.String()),
        sa.Column('risk_score', sa.Float()),
        sa.Column('status', sa.String(), server_default='open'),
        sa.Column('false_positive', sa.Boolean(), server_default='false'),
        sa.Column('discovered_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('first_seen', sa.DateTime()),
        sa.Column('last_seen', sa.DateTime()),
        sa.Column('fixed_at', sa.DateTime()),
        sa.Column('raw_finding', sa.JSON())
    )

    # Create indexes on vulnerability_findings
    op.create_index('ix_vulnerability_findings_scan_id', 'vulnerability_findings', ['scan_id'])
    op.create_index('ix_vulnerability_findings_severity', 'vulnerability_findings', ['severity'])
    op.create_index('ix_vulnerability_findings_status', 'vulnerability_findings', ['status'])
    op.create_index('ix_vulnerability_findings_discovered_at', 'vulnerability_findings', ['discovered_at'])

    # Create vulnerability_mitigations table
    op.create_table(
        'vulnerability_mitigations',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('finding_id', sa.Integer(), sa.ForeignKey('vulnerability_findings.id')),
        sa.Column('recommendation', sa.String(), nullable=False),
        sa.Column('priority', sa.Integer()),
        sa.Column('estimated_effort', sa.String()),
        sa.Column('remediation_type', sa.String()),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('code_snippets', sa.JSON()),
        sa.Column('compliance_impact', sa.JSON()),
        sa.Column('business_impact', sa.String())
    )

    # Create threat_intel_data table
    op.create_table(
        'threat_intel_data',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('finding_id', sa.Integer(), sa.ForeignKey('vulnerability_findings.id')),
        sa.Column('source', sa.String(), nullable=False),
        sa.Column('threat_type', sa.String()),
        sa.Column('confidence_score', sa.Float()),
        sa.Column('last_seen', sa.DateTime()),
        sa.Column('exploit_available', sa.Boolean(), server_default='false'),
        sa.Column('exploit_details', sa.JSON()),
        sa.Column('patch_available', sa.Boolean(), server_default='false'),
        sa.Column('patch_info', sa.JSON()),
        sa.Column('raw_data', sa.JSON()),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now())
    )

    # Create index on threat_intel_data
    op.create_index('ix_threat_intel_data_finding_id', 'threat_intel_data', ['finding_id'])

def downgrade():
    op.drop_table('threat_intel_data')
    op.drop_table('vulnerability_mitigations')
    op.drop_table('vulnerability_findings')
    op.drop_table('security_scans')
    op.drop_table('batch_scans')