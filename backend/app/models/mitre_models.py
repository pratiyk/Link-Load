"""MITRE technique and CAPEC mappings."""
from sqlalchemy import Column, Integer, String, JSON, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import enum

from app.models.threat_intel_models import (
    MITRETactic,
    MITRETechnique,
)

class TTPType(str, enum.Enum):
    """Types of Tactics, Techniques, and Procedures."""
    TACTIC = "tactic"
    TECHNIQUE = "technique"
    SUB_TECHNIQUE = "sub_technique"
    PROCEDURE = "procedure"

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
    typical_likelihood = Column(String)
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

_existing_assoc = Base.metadata.tables.get('technique_capec_association')
if _existing_assoc is not None:
    technique_capec_association = _existing_assoc
else:
    technique_capec_association = Table(
        'technique_capec_association',
        Base.metadata,
        Column('technique_id', String, ForeignKey('mitre_techniques.technique_id')),
        Column('pattern_id', String, ForeignKey('capec_patterns.pattern_id'))
    )

if not hasattr(MITRETechnique, "sub_techniques"):
    MITRETechnique.sub_techniques = relationship(
        'MITRESubTechnique',
        back_populates='parent_technique'
    )

if not hasattr(MITRETechnique, "capec_patterns"):
    MITRETechnique.capec_patterns = relationship(
        'CAPEC',
        secondary='technique_capec_association',
        back_populates='techniques'
    )