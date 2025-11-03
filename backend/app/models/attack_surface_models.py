import uuid
from sqlalchemy import Column, String, Integer, DateTime, JSON, Float, Text
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

Base = declarative_base()

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class AssetType(str, Enum):
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    URL = "url"
    PORT = "port"
    SERVICE = "service"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AttackSurfaceScan(Base):
    __tablename__ = "attack_surface_scans"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    target_domain = Column(String, nullable=False, index=True)
    status = Column(String, default=ScanStatus.PENDING)
    progress = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scan_config = Column(JSON, nullable=True)
    total_assets_found = Column(Integer, default=0)
    high_risk_assets = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

class DiscoveredAsset(Base):
    __tablename__ = "discovered_assets"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, nullable=False, index=True)
    asset_type = Column(String, nullable=False)
    name = Column(String, nullable=False)
    risk_level = Column(String, default=RiskLevel.LOW)
    risk_score = Column(Float, default=0.0)
    ports = Column(JSON, nullable=True)
    services = Column(JSON, nullable=True)
    asset_metadata = Column(JSON, nullable=True)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())

class ScanConfigRequest(BaseModel):
    target_domain: str = Field(..., description="Domain to scan")
    api_sources: List[str] = Field(default=["subfinder","crt"], description="Discovery sources")
    port_scan_enabled: bool = Field(default=False)
    port_range: str = Field(default="top-1000")
    max_subdomains: int = Field(default=1000)

class ScanResponse(BaseModel):
    id: str
    target_domain: str
    status: str
    progress: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    total_assets_found: int
    high_risk_assets: int
    error_message: Optional[str]
    class Config:
        from_attributes = True

class AssetResponse(BaseModel):
    id: str
    scan_id: str
    asset_type: str
    name: str
    risk_level: str
    risk_score: float
    ports: Optional[List[int]]
    services: Optional[Dict[str,Any]]
    discovered_at: datetime
    asset_metadata: Optional[Dict[str,Any]]
    class Config:
        from_attributes = True

class ScanSummaryResponse(BaseModel):
    scan: ScanResponse
    assets_summary: Dict[str,int]
    risk_distribution: Dict[str,int]
    top_risks: List[AssetResponse]
    recent_discoveries: List[AssetResponse]

class WebSocketMessage(BaseModel):
    type: str
    data: Dict[str,Any]
