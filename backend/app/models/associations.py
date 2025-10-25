"""Database association tables for many-to-many relationships."""
from sqlalchemy import Table, Column, Integer, String, ForeignKey, MetaData
from app.database import Base

# Use Base.metadata for table definitions
metadata = Base.metadata

# Association table for vulnerabilities and MITRE techniques
# Only create if it doesn't exist yet
if 'vulnerability_technique_association' not in Base.metadata.tables:
    vulnerability_technique_association = Table(
        'vulnerability_technique_association',
        metadata,
        Column('vulnerability_id', Integer, primary_key=True),
        Column('technique_id', String, primary_key=True),
        extend_existing=True  # Allow table redefinition
    )
else:
    vulnerability_technique_association = Base.metadata.tables['vulnerability_technique_association']

# Association table for MITRE techniques and tactics
if 'technique_tactic_association' not in Base.metadata.tables:
    technique_tactic_association = Table(
        'technique_tactic_association',
        metadata,
        Column('technique_id', String, primary_key=True),
        Column('tactic_id', String, primary_key=True),
        extend_existing=True  # Allow table redefinition
    )
else:
    technique_tactic_association = Base.metadata.tables['technique_tactic_association']

# Association table for MITRE techniques and CAPEC patterns
if 'technique_capec_association' not in Base.metadata.tables:
    technique_capec_association = Table(
        'technique_capec_association',
        metadata,
        Column('technique_id', String, primary_key=True),
        Column('pattern_id', String, primary_key=True),
        extend_existing=True  # Allow table redefinition
    )
else:
    technique_capec_association = Base.metadata.tables['technique_capec_association']