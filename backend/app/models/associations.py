"""Database association tables for many-to-many relationships."""
from sqlalchemy import Table, Column, Integer, String, ForeignKey, MetaData
from app.database import Base

# Use Base.metadata for table definitions
metadata = Base.metadata

# Association table for vulnerabilities and MITRE techniques
vulnerability_technique_association = Table(
    'vulnerability_technique_association',
    metadata,
    Column('vulnerability_id', Integer, ForeignKey('vulnerability_data.id'), primary_key=True),
    Column('technique_id', String, ForeignKey('mitre_techniques.technique_id'), primary_key=True),
    extend_existing=True  # Allow table redefinition
)

# Association table for MITRE techniques and tactics
technique_tactic_association = Table(
    'technique_tactic_association',
    metadata,
    Column('technique_id', String, ForeignKey('mitre_techniques.technique_id'), primary_key=True),
    Column('tactic_id', String, ForeignKey('mitre_tactics.tactic_id'), primary_key=True),
    extend_existing=True  # Allow table redefinition
)

# Association table for MITRE techniques and CAPEC patterns
technique_capec_association = Table(
    'technique_capec_association',
    metadata,
    Column('technique_id', String, ForeignKey('mitre_techniques.technique_id'), primary_key=True),
    Column('pattern_id', String, ForeignKey('capec_patterns.pattern_id'), primary_key=True),
    extend_existing=True  # Allow table redefinition
)