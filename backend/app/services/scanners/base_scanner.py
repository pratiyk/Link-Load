from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class ScannerConfig(BaseModel):
    """Base configuration for vulnerability scanners"""
    target_url: str = Field(..., description="Target URL to scan")
    scan_types: List[str] = Field(default_factory=list, description="Types of scans to perform")
    include_passive: bool = Field(default=True, description="Include passive scanning")
    ajax_spider: bool = Field(default=False, description="Use AJAX Spider")
    deep_scan: bool = Field(default=False, description="Enable deep/thorough scanning mode")
    include_low_risk: bool = Field(default=True, description="Include low risk findings")
    auth_config: Optional[Dict[str, Any]] = Field(default=None, description="Authentication configuration")
    max_scan_duration: int = Field(default=3600, description="Maximum scan duration in seconds")
    risk_threshold: float = Field(default=0.0, description="Minimum risk threshold for reporting")

class ScannerError(Exception):
    """Base class for scanner errors"""
    pass

class ScanInitializationError(ScannerError):
    """Error during scanner initialization"""
    pass

class ScanExecutionError(ScannerError):
    """Error during scan execution"""
    pass

class Vulnerability(BaseModel):
    """Standardized vulnerability model"""
    name: str = Field(..., description="Vulnerability name/title")
    description: Optional[str] = Field(None, description="Detailed description")
    severity: str = Field(..., description="Vulnerability severity")
    confidence: str = Field(..., description="Detection confidence")
    url: Optional[str] = Field(None, description="Affected URL")
    parameter: Optional[str] = Field(None, description="Affected parameter")
    evidence: Optional[str] = Field(None, description="Evidence of vulnerability")
    solution: Optional[str] = Field(None, description="Remediation guidance")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    tags: List[str] = Field(default_factory=list, description="Vulnerability tags")
    raw_finding: Optional[Dict[str, Any]] = Field(None, description="Raw scanner output")

class ScanResult(BaseModel):
    """Standardized scan result model"""
    scan_id: str = Field(..., description="Unique scan identifier")
    target_url: str = Field(..., description="Target URL that was scanned")
    start_time: datetime = Field(..., description="Scan start time")
    end_time: Optional[datetime] = Field(None, description="Scan completion time")
    status: str = Field(..., description="Current scan status")
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list, description="Detected vulnerabilities")
    scan_log: List[str] = Field(default_factory=list, description="Scan log messages")
    raw_findings: Dict[str, Any] = Field(default_factory=dict, description="Raw scanner output")

    class Config:
        arbitrary_types_allowed = True

class BaseScanner(ABC):
    """Base class for all vulnerability scanners"""
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the scanner with required configuration"""
        pass

    @abstractmethod
    async def start_scan(self, config: ScannerConfig) -> str:
        """Start a new scan with given configuration"""
        pass
    
    @abstractmethod
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status of a scan"""
        pass

    @abstractmethod
    async def get_scan_results(self, scan_id: str) -> ScanResult:
        """Get results of a completed scan"""
        pass

    @abstractmethod
    async def stop_scan(self, scan_id: str) -> bool:
        """Stop an ongoing scan"""
        pass

    @abstractmethod
    async def cleanup_scan(self, scan_id: str) -> bool:
        """Clean up resources from a completed scan"""
        pass

    @abstractmethod
    async def shutdown(self) -> bool:
        """Shutdown scanner and cleanup resources"""
        pass