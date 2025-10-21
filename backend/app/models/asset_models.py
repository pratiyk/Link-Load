from sqlalchemy import Column, Integer, String, DateTime, JSON, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class DiscoveredAsset(Base):
    __tablename__ = "discovered_assets"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_type = Column(String, nullable=False)  # e.g., domain, ip, url
    identifier = Column(String, nullable=False)  # The actual asset value
    asset_metadata = Column(JSON)  # Additional asset information
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    risk_score = Column(Float, default=0.0)  # Calculated risk score for the asset

    # Relationships
    vulnerabilities = relationship("VulnerabilityData", back_populates="asset")