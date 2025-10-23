from pydantic import BaseModel, HttpUrl, Field, validator, model_validator
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class ScanType(str, Enum):
    ZAP_BASELINE   = "zap_baseline"
    ZAP_ACTIVE     = "zap_active"
    NUCLEI         = "nuclei"
    WAPITI         = "wapiti"
    COMPREHENSIVE  = "comprehensive"

class ScanStatus(str, Enum):
    PENDING    = "pending"
    QUEUED     = "queued"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    CANCELLED  = "cancelled"
    TIMEOUT    = "timeout"

class BatchScanStatus(str, Enum):
    PENDING    = "pending"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    CANCELLED  = "cancelled"

class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"

class ScanRequest(BaseModel):
    target_url: HttpUrl = Field(..., description="Target URL to scan")
    scan_types: List[ScanType] = Field(..., min_items=1, description="Types of scans to perform")
    include_low_risk: bool = Field(False, description="Include low-risk findings")
    max_scan_time: int = Field(3600, ge=300, le=7200, description="Maximum scan time in seconds")

    # Authentication
    authenticated: bool = Field(False, description="Perform authenticated scan")
    auth_username: Optional[str] = Field(None, description="Username for authentication")
    auth_password: Optional[str] = Field(None, description="Password for authentication")
    auth_type: Optional[str] = Field("form", description="Authentication type")
    login_url: Optional[HttpUrl] = Field(None, description="Login URL for form auth")

    # Advanced options
    custom_headers: Optional[Dict[str, str]] = Field(None, description="Custom HTTP headers")
    user_agent: Optional[str] = Field(None, description="Custom User-Agent string")
    proxy_url: Optional[str] = Field(None, description="Proxy URL")
    follow_redirects: bool = Field(True, description="Follow HTTP redirects")
    scan_depth: int = Field(2, ge=1, le=5, description="Scan depth level")

    # Nuclei specific
    nuclei_templates: Optional[List[str]] = Field(None, description="Specific Nuclei templates")
    nuclei_tags: Optional[List[str]] = Field(None, description="Nuclei template tags")
    nuclei_severity: Optional[List[str]] = Field(None, description="Nuclei severity filter")

    # Notifications
    notify_on_completion: bool = Field(False, description="Send notification when scan completes")
    notification_email: Optional[str] = Field(None, description="Email for notifications")
    notification_webhook: Optional[HttpUrl] = Field(None, description="Webhook URL for notifications")

    @validator("auth_password")
    def validate_auth_password(cls, v, values):
        if values.get("authenticated") and not v:
            raise ValueError("Password required for authenticated scans")
        return v


class BatchScanConfig(ScanRequest):
    target_url: Optional[HttpUrl] = Field(
        default=None,
        description="Target URL supplied per batch item",
    )

    class Config:
        extra = "allow"

class Vulnerability(BaseModel):
    id: str = Field(..., description="Unique vulnerability ID")
    name: str = Field(..., description="Vulnerability name")
    description: str = Field(..., description="Detailed description")
    severity: SeverityLevel = Field(..., description="Severity level")
    confidence: str = Field(..., description="Confidence level")

    # Location information
    url: Optional[str] = Field(None, description="Affected URL")
    parameter: Optional[str] = Field(None, description="Vulnerable parameter")
    method: Optional[str] = Field(None, description="HTTP method")

    # Technical details
    solution: Optional[str] = Field(None, description="Remediation advice")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    evidence: Optional[str] = Field(None, description="Evidence/proof of vulnerability")
    payload: Optional[str] = Field(None, description="Attack payload used")

    # Classification
    scanner: str = Field(..., description="Scanner that found the vulnerability")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    owasp_category: Optional[str] = Field(None, description="OWASP Top 10 category")

    # Risk assessment
    exploitability: Optional[str] = Field(None, description="Exploitability rating")
    impact: Optional[str] = Field(None, description="Impact rating")
    risk_score: Optional[float] = Field(None, ge=0, le=10, description="CVSS-like risk score")

    # Timestamps
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    first_seen: Optional[datetime] = Field(None, description="First time this vuln was seen")
    last_seen: Optional[datetime] = Field(None, description="Last time this vuln was confirmed")

    # Status
    status: str = Field("open", description="Vulnerability status")
    false_positive: bool = Field(False, description="Marked as false positive")

    class Config:
        use_enum_values = True

class ScanProgress(BaseModel):
    scan_id: str
    current_step: str
    progress_percentage: float = Field(ge=0, le=100)
    estimated_time_remaining: Optional[int] = None
    scanned_urls: int = 0
    total_urls: int = 0
    vulnerabilities_found: int = 0
    last_updated: datetime = Field(default_factory=datetime.utcnow)

class ScanSummary(BaseModel):
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

class ScanResult(BaseModel):
    scan_id: str = Field(..., description="Unique scan identifier")
    user_id: str = Field(..., description="User who initiated the scan")
    target_url: str = Field(..., description="Target URL")
    scan_types: List[ScanType] = Field(..., description="Types of scans performed")
    status: ScanStatus = Field(..., description="Current scan status")
    started_at: datetime = Field(..., description="Scan start time")
    completed_at: Optional[datetime] = Field(None, description="Scan completion time")
    duration: Optional[int] = Field(None, description="Scan duration in seconds")
    progress: Optional[ScanProgress] = Field(None, description="Scan progress information")
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    scan_config: Dict[str, Any] = Field(default_factory=dict)
    environment_info: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    scan_quality_score: Optional[float] = Field(None, ge=0, le=1)
    coverage_percentage: Optional[float] = Field(None, ge=0, le=100)
    report_url: Optional[str] = Field(None, description="URL to detailed report")
    shared: bool = Field(False, description="Whether scan is shared")
    tags: List[str] = Field(default_factory=list, description="User-defined tags")

    class Config:
        use_enum_values = True

class ScanFilter(BaseModel):
    status: Optional[List[ScanStatus]] = None
    scan_types: Optional[List[ScanType]] = None
    severity_levels: Optional[List[SeverityLevel]] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    tags: Optional[List[str]] = None
    search_query: Optional[str] = None

class ScanExport(BaseModel):
    format: str = Field(..., pattern="^(json|pdf|csv|html|xml)$")
    include_false_positives: bool = Field(False)
    include_low_risk: bool = Field(True)
    sections: List[str] = Field(default=["summary", "vulnerabilities", "recommendations"])
    custom_branding: bool = Field(False)

class BatchScanRequest(BaseModel):
    targets: List[HttpUrl] = Field(..., min_items=1, description="List of target URLs to scan")
    scan_config: BatchScanConfig = Field(..., description="Scan configuration to apply to all targets")
    concurrent_scans: int = Field(5, ge=1, le=20, description="Number of concurrent scans")
    notify_on_completion: bool = Field(False, description="Send notification when batch completes")
    force_new_scan: bool = Field(False, description="Force new scans ignoring cache")

    @model_validator(mode="before")
    @classmethod
    def _coerce_scan_config(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        scan_config = data.get("scan_config")
        if isinstance(scan_config, ScanRequest):
            data = dict(data)
            data["scan_config"] = BatchScanConfig.model_validate(scan_config.model_dump())
        return data

class BatchScan(BaseModel):
    batch_id: str = Field(..., description="Unique batch identifier")
    user_id: str = Field(..., description="User who initiated the batch")
    status: BatchScanStatus = Field(..., description="Current batch status")
    total_targets: int = Field(..., description="Total number of targets")
    completed_targets: int = Field(0, description="Number of completed scans")
    failed_targets: int = Field(0, description="Number of failed scans")
    scan_config: Dict[str, Any] = Field(..., description="Scan configuration")
    started_at: datetime = Field(..., description="Batch start time")
    completed_at: Optional[datetime] = Field(None, description="Batch completion time")
    scan_results: List[ScanResult] = Field(default_factory=list, description="Results of completed scans")