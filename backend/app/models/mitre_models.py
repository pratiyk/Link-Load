"""MITRE technique and CAPEC mappings."""
from sqlalchemy import Column, Integer, String, Float, JSON, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
from typing import List, Dict, Any
from datetime import datetime
import enum

class TTPType(str, enum.Enum):
    """Types of Tactics, Techniques, and Procedures."""
    TACTIC = "tactic"
    TECHNIQUE = "technique"
    SUB_TECHNIQUE = "sub_technique"
    PROCEDURE = "procedure"

class MITRETactic(Base):
    """MITRE ATT&CK Tactics."""
    __tablename__ = 'mitre_tactics'

    tactic_id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String)
    url = Column(String)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Relationships
    techniques = relationship(
        'MITRETechnique',
        secondary='technique_tactic_association',
        back_populates='tactics'
    )

class MITRETechnique(Base):
    """MITRE ATT&CK Techniques."""
    __tablename__ = 'mitre_techniques'

    technique_id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String)
    detection = Column(String)
    url = Column(String)
    data_sources = Column(JSON)
    platforms = Column(JSON)
    permissions_required = Column(JSON)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Relationships
    tactics = relationship(
        'MITRETactic',
        secondary='technique_tactic_association',
        back_populates='techniques'
    )
    vulnerabilities = relationship(
        'VulnerabilityData',
        secondary='vulnerability_technique_association',
        back_populates='mitre_techniques'
    )
    sub_techniques = relationship(
        'MITRESubTechnique',
        back_populates='parent_technique'
    )
    capec_patterns = relationship(
        'CAPEC',
        secondary='technique_capec_association',
        back_populates='techniques'
    )

class MITRESubTechnique(Base):
    """MITRE ATT&CK Sub-techniques."""
    __tablename__ = 'mitre_sub_techniques'

    sub_technique_id = Column(String, primary_key=True)
    parent_technique_id = Column(String, ForeignKey('mitre_techniques.technique_id'))
    name = Column(String, nullable=False)
    description = Column(String)
    detection = Column(String)
    url = Column(String)
    data_sources = Column(JSON)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Relationships
    parent_technique = relationship(
        'MITRETechnique',
        back_populates='sub_techniques'
    )
    procedures = relationship(
        'Procedure',
        back_populates='sub_technique'
    )

class Procedure(Base):
    """Specific attack procedures."""
    __tablename__ = 'procedures'

    id = Column(Integer, primary_key=True)
    sub_technique_id = Column(String, ForeignKey('mitre_sub_techniques.sub_technique_id'))
    name = Column(String, nullable=False)
    description = Column(String)
    implementation = Column(String)
    detection = Column(String)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Relationships
    sub_technique = relationship(
        'MITRESubTechnique',
        back_populates='procedures'
    )

class CAPEC(Base):
    """Common Attack Pattern Enumeration and Classification."""
    __tablename__ = 'capec_patterns'

    pattern_id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String)
    likelihood = Column(String)
    typical_severity = Column(String)
    prerequisites = Column(JSON)
    mitigations = Column(JSON)
    mitre_technique_ids = Column(JSON)  # List of related technique IDs
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Relationships
    techniques = relationship(
        'MITRETechnique',
        secondary='technique_capec_association',
        back_populates='capec_patterns'
    )

# Association tables
technique_tactic_association = Base.metadata.tables.get('technique_tactic_association') or Table(
    'technique_tactic_association',
    Base.metadata,
    Column('technique_id', String, ForeignKey('mitre_techniques.technique_id')),
    Column('tactic_id', String, ForeignKey('mitre_tactics.tactic_id'))
)

vulnerability_technique_association = Base.metadata.tables.get('vulnerability_technique_association') or Table(
    'vulnerability_technique_association',
    Base.metadata,
    Column('vulnerability_id', Integer, ForeignKey('vulnerability_data.id')),
    Column('technique_id', String, ForeignKey('mitre_techniques.technique_id'))
)

technique_capec_association = Base.metadata.tables.get('technique_capec_association') or Table(
    'technique_capec_association',
    Base.metadata,
    Column('technique_id', String, ForeignKey('mitre_techniques.technique_id')),
    Column('pattern_id', String, ForeignKey('capec_patterns.pattern_id'))
)