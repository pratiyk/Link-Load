from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, HttpUrl, ValidationInfo, field_validator

class ScanConfig(BaseModel):
    scan_depth: str = "normal"
    concurrent_requests: int = 10
    request_delay: float = 0.1
    auth_required: bool = False
    auth_config: Optional[Dict[str, str]] = None
    excluded_paths: List[str] = []
    custom_headers: Dict[str, str] = {}
    scan_timeout: int = 3600  # 5 minutes to 24 hours

    @field_validator('concurrent_requests')
    @classmethod
    def validate_concurrent_requests(cls, v: int) -> int:
        if not 1 <= v <= 50:
            raise ValueError('concurrent_requests must be between 1 and 50')
        return v

    @field_validator('request_delay')
    @classmethod
    def validate_request_delay(cls, v: float) -> float:
        if not 0 <= v <= 5.0:
            raise ValueError('request_delay must be between 0 and 5.0 seconds')
        return v

    @field_validator('scan_timeout')
    @classmethod
    def validate_scan_timeout(cls, v: int) -> int:
        if not 300 <= v <= 86400:
            raise ValueError('scan_timeout must be between 300 and 86400 seconds')
        return v

    @field_validator('scan_depth')
    @classmethod
    def validate_scan_depth(cls, v: str) -> str:
        allowed = ['quick', 'normal', 'deep']
        if v not in allowed:
            raise ValueError(f'scan_depth must be one of {allowed}')
        return v

    @field_validator('excluded_paths')
    @classmethod
    def validate_paths(cls, v: List[str]) -> List[str]:
        for path in v:
            if not path.startswith('/'):
                raise ValueError(f'Path must start with /: {path}')
        return v

    @field_validator('custom_headers')
    @classmethod
    def validate_headers(cls, v: Dict[str, str]) -> Dict[str, str]:
        disallowed = ['cookie', 'authorization']
        for header in v.keys():
            if header.lower() in disallowed:
                raise ValueError(f'Header not allowed: {header}')
        return v

class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_types: List[str]
    scan_config: ScanConfig = ScanConfig()

    @field_validator('scan_types')
    @classmethod
    def validate_scan_types(cls, v: List[str]) -> List[str]:
        allowed = ['zap', 'nuclei', 'wapiti']
        for scan_type in v:
            if scan_type not in allowed:
                raise ValueError(f'Invalid scan type: {scan_type}')
        if not v:
            raise ValueError('At least one scan type required')
        return v

class Finding(BaseModel):
    id: str
    scan_id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    proof_of_concept: Optional[str] = None
    affected_components: List[str] = []
    technical_details: Optional[str] = None
    discovered_at: datetime
    verified: bool = False
    false_positive: bool = False
    exploit_available: bool = False
    remediation_steps: Optional[str] = None

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = ['critical', 'high', 'medium', 'low', 'info']
        if v.lower() not in allowed:
            raise ValueError(f'Invalid severity: {v}')
        return v.lower()

    @field_validator('cvss_score')
    @classmethod
    def validate_cvss(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not 0 <= v <= 10:
            raise ValueError('CVSS score must be between 0 and 10')
        return v

class ScanSchedule(BaseModel):
    target_url: HttpUrl
    scan_types: List[str]
    scan_config: ScanConfig
    schedule_type: str
    cron_expression: Optional[str] = None
    interval_seconds: Optional[int] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    enabled: bool = True

    @field_validator('schedule_type')
    @classmethod
    def validate_schedule_type(cls, v: str) -> str:
        if v not in ['cron', 'interval']:
            raise ValueError('Schedule type must be either cron or interval')
        return v

    @field_validator('interval_seconds')
    @classmethod
    def validate_interval(cls, v: Optional[int], info: ValidationInfo) -> Optional[int]:
        schedule_type = info.data.get('schedule_type')
        if schedule_type == 'interval':
            if v is None:
                raise ValueError('interval_seconds required for interval schedule')
            if v < 3600:  # Minimum 1 hour
                raise ValueError('Interval must be at least 3600 seconds (1 hour)')
        return v

    @field_validator('cron_expression')
    @classmethod
    def validate_cron(cls, v: Optional[str], info: ValidationInfo) -> Optional[str]:
        schedule_type = info.data.get('schedule_type')
        if schedule_type == 'cron' and not v:
            raise ValueError('cron_expression required for cron schedule')
        return v

class BusinessContext(BaseModel):
    asset_criticality: str
    sensitive_data: bool = False
    customer_facing: bool = False
    revenue_impact: bool = False
    compliance_required: bool = False
    data_classification: str = 'internal'
    business_unit: Optional[str] = None
    technical_owner: Optional[str] = None
    business_owner: Optional[str] = None

    @field_validator('asset_criticality')
    @classmethod
    def validate_criticality(cls, v: str) -> str:
        allowed = ['critical', 'high', 'medium', 'low']
        if v.lower() not in allowed:
            raise ValueError(f'Invalid criticality level: {v}')
        return v.lower()

    @field_validator('data_classification')
    @classmethod
    def validate_classification(cls, v: str) -> str:
        allowed = ['public', 'internal', 'confidential', 'restricted']
        if v.lower() not in allowed:
            raise ValueError(f'Invalid data classification: {v}')
        return v.lower()