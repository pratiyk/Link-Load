"""Models for threat intelligence and MITRE ATT&CK mappings."""
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON, Table
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from typing import List, Optional
from datetime import datetime
from app.database import Base

# Association table for techniques and tactics
technique_tactic_association = Table(
    'technique_tactic_association',
    Base.metadata,
    Column('technique_id', String, ForeignKey('mitre_techniques.technique_id')),
    Column('tactic_id', String, ForeignKey('mitre_tactics.tactic_id'))
)

# Association table for vulnerabilities and techniques
vulnerability_technique_association = Table(
    'vulnerability_technique_association',
    Base.metadata,
    Column('vulnerability_id', Integer, ForeignKey('vulnerabilities.id')),
    Column('technique_id', String, ForeignKey('mitre_techniques.technique_id'))
)

class MITRETactic(Base):
    """MITRE ATT&CK Tactics."""
    __tablename__ = 'mitre_tactics'

    tactic_id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String)
    url = Column(String)
    matrix = Column(String)  # enterprise, mobile, ics
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Relationships
    techniques = relationship(
        'MITRETechnique',
        secondary=technique_tactic_association,
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
        secondary=technique_tactic_association,
        back_populates='techniques'
    )
    vulnerabilities = relationship(
        'VulnerabilityData',
        secondary=vulnerability_technique_association,
        back_populates='mitre_techniques'
    )

class ThreatIntelligence(Base):
    """Threat Intelligence data."""
    __tablename__ = 'threat_intelligence'

    id = Column(Integer, primary_key=True)
    source = Column(String, nullable=False)
    threat_type = Column(String, nullable=False)  # malware, ransomware, apt, etc.
    name = Column(String)
    description = Column(String)
    confidence_score = Column(Float)
    severity = Column(Float)
    raw_data = Column(JSON)
    indicators = Column(JSON)  # IPs, domains, hashes
    references = Column(JSON)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Relationships
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'))
    vulnerability = relationship('VulnerabilityData', back_populates='threat_intel')

class RiskScore(Base):
    """Risk scoring for vulnerabilities."""
    __tablename__ = 'risk_scores'

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'), unique=True)
    base_score = Column(Float, nullable=False)
    temporal_score = Column(Float)
    environmental_score = Column(Float)
    exploit_likelihood = Column(Float)
    impact_score = Column(Float)
    ml_confidence = Column(Float)
    factors = Column(JSON)  # Factors contributing to the score
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Relationships
    vulnerability = relationship('VulnerabilityData', back_populates='risk_score')