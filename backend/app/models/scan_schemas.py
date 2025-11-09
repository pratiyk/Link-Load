"""
Pydantic models for security scanning API schemas.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from enum import Enum

class ScannerType(str, Enum):
    """Types of supported security scanners"""
    ZAP = "zap"
    NUCLEI = "nuclei"
    WAPITI = "wapiti"
    CUSTOM = "custom"

class ScanStatus(str, Enum):
    """Status of a security scan"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

class SeverityLevel(str, Enum):
    """Standardized severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanRequest(BaseModel):
    """Request to start a new security scan"""
    target_url: str = Field(..., description="Target URL to scan")
    scan_types: List[ScannerType] = Field(..., description="Types of scans to perform")
    include_passive: bool = Field(default=True, description="Include passive scanning")
    ajax_spider: bool = Field(default=False, description="Use AJAX Spider")
    max_scan_time: int = Field(default=3600, description="Maximum scan duration in seconds")
    auth_config: Optional[dict] = Field(default=None, description="Authentication configuration")
    scan_policy: Optional[dict] = Field(default=None, description="Scan policy configuration")
    include_low_risk: bool = Field(default=True, description="Include low risk findings")
    force_new_scan: bool = Field(default=False, description="Force new scan ignoring cache")

class ScanProgress(BaseModel):
    """Real-time scan progress information"""
    scan_id: str
    current_step: str
    progress_percentage: float = Field(ge=0, le=100)
    estimated_time_remaining: Optional[int] = None
    scanned_urls: int = 0
    total_urls: int = 0
    vulnerabilities_found: int = 0
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ScanSummary(BaseModel):
    """Summary of scan results"""
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    false_positive_count: int = 0
    risk_score: float = 0.0
    compliance_score: float = 0.0
    scan_coverage: float = 0.0

class VulnerabilityFinding(BaseModel):
    """Standardized vulnerability finding model"""
    id: Optional[int] = None
    scan_id: str
    scanner: str
    name: str
    description: Optional[str] = None
    severity: SeverityLevel
    confidence: str

    # Location information
    url: Optional[str] = None
    parameter: Optional[str] = None
    method: Optional[str] = None

    # Technical details
    solution: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    evidence: Optional[str] = None
    payload: Optional[str] = None
    
    # Classification
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    
    # Analysis
    attack_complexity: Optional[str] = None
    attack_vector: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    impact: Optional[str] = None
    risk_score: Optional[float] = None
    
    # Raw data
    raw_finding: Optional[Dict[str, Any]] = None

class ScanResult(BaseModel):
    """Complete scan results"""
    scan_id: str = Field(..., description="Unique scan identifier")
    user_id: str = Field(..., description="User who initiated the scan")
    target_url: str = Field(..., description="Target URL")
    scan_types: List[ScannerType] = Field(..., description="Types of scans performed")
    status: ScanStatus = Field(..., description="Current scan status")
    started_at: datetime = Field(..., description="Scan start time")
    completed_at: Optional[datetime] = Field(None, description="Scan completion time")
    duration: Optional[int] = Field(None, description="Scan duration in seconds")
    progress: Optional[ScanProgress] = Field(None, description="Scan progress information")
    summary: ScanSummary = Field(default_factory=ScanSummary, description="Scan summary")
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list, description="Detected vulnerabilities")
    scan_config: dict = Field(default_factory=dict, description="Scan configuration")
    environment_info: dict = Field(default_factory=dict, description="Environment information")
    errors: List[str] = Field(default_factory=list, description="Error messages")

    class Config:
        use_enum_values = True