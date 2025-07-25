from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, JSON, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum as PyEnum
import uuid

Base = declarative_base()

class ScanStatus(PyEnum):
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class AssetType(PyEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    SERVICE = "service"
    PORT = "port"

class RiskLevel(PyEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# SQLAlchemy Models
class AttackSurfaceScan(Base):
    __tablename__ = "attack_surface_scans"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_domain = Column(String, nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    progress = Column(Integer, default=0)
    total_assets_found = Column(Integer, default=0)
    high_risk_assets = Column(Integer, default=0)
    scan_config = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Relationships
    assets = relationship("DiscoveredAsset", back_populates="scan")

class DiscoveredAsset(Base):
    __tablename__ = "discovered_assets"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("attack_surface_scans.id"))
    asset_type = Column(Enum(AssetType))
    name = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    ports = Column(JSON)  # List of open ports
    services = Column(JSON)  # Service information
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.LOW)
    risk_score = Column(Float, default=0.0)
    risk_factors = Column(JSON)  # List of risk factors
    threat_intel = Column(JSON)  # Threat intelligence data
    vulnerabilities = Column(JSON)  # Known vulnerabilities
    ssl_info = Column(JSON)  # SSL certificate information
    technologies = Column(JSON)  # Detected technologies
    geolocation = Column(JSON)  # Geographic information
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("AttackSurfaceScan", back_populates="assets")

# Pydantic Models for API
class ScanConfigRequest(BaseModel):
    target_domain: str = Field(..., description="Target domain to scan")
    max_subdomains: int = Field(default=1000, description="Maximum subdomains to discover")
    port_scan_enabled: bool = Field(default=True, description="Enable port scanning")
    port_range: str = Field(default="top1000", description="Port range to scan")
    service_detection: bool = Field(default=True, description="Enable service detection")
    stealth_mode: bool = Field(default=False, description="Enable stealth scanning")
    api_sources: List[str] = Field(default=["subfinder", "amass", "crt"], description="API sources to use")

class AssetResponse(BaseModel):
    id: str
    asset_type: str
    name: str
    ip_address: Optional[str] = None
    ports: List[int] = []
    services: Dict[str, Any] = {}
    risk_level: str
    risk_score: float
    risk_factors: List[str] = []
    threat_intel: Dict[str, Any] = {}
    vulnerabilities: List[Dict[str, Any]] = []
    ssl_info: Dict[str, Any] = {}
    technologies: List[str] = []
    geolocation: Dict[str, Any] = {}
    discovered_at: datetime
    last_seen: datetime
    
    class Config:
        from_attributes = True

class ScanResponse(BaseModel):
    id: str
    target_domain: str
    status: str
    progress: int
    total_assets_found: int
    high_risk_assets: int
    scan_config: Dict[str, Any]
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    
    class Config:
        from_attributes = True

class ScanSummaryResponse(BaseModel):
    scan: ScanResponse
    assets_summary: Dict[str, int]
    risk_distribution: Dict[str, int]
    top_risks: List[AssetResponse]
    recent_discoveries: List[AssetResponse]

class WebSocketMessage(BaseModel):
    type: str  # "progress", "asset_discovered", "scan_complete", "error"
    data: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
