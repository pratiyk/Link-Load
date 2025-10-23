from typing import List, Dict, Any, Optional
from pydantic import BaseModel, HttpUrl, constr, confloat, conint, validator
from datetime import datetime

class ScanConfig(BaseModel):
    scan_depth: str = "normal"
    concurrent_requests: int = 10
    request_delay: float = 0.1
    auth_required: bool = False
    auth_config: Optional[Dict[str, str]] = None
    excluded_paths: List[str] = []
    custom_headers: Dict[str, str] = {}
    scan_timeout: int = 3600  # 5 minutes to 24 hours

    @validator('concurrent_requests')
    def validate_concurrent_requests(cls, v):
        if not 1 <= v <= 50:
            raise ValueError('concurrent_requests must be between 1 and 50')
        return v

    @validator('request_delay')
    def validate_request_delay(cls, v):
        if not 0 <= v <= 5.0:
            raise ValueError('request_delay must be between 0 and 5.0 seconds')
        return v

    @validator('scan_timeout')
    def validate_scan_timeout(cls, v):
        if not 300 <= v <= 86400:
            raise ValueError('scan_timeout must be between 300 and 86400 seconds')
        return v

    @validator('scan_depth')
    def validate_scan_depth(cls, v):
        allowed = ['quick', 'normal', 'deep']
        if v not in allowed:
            raise ValueError(f'scan_depth must be one of {allowed}')
        return v

    @validator('excluded_paths')
    def validate_paths(cls, v):
        for path in v:
            if not path.startswith('/'):
                raise ValueError(f'Path must start with /: {path}')
        return v

    @validator('custom_headers')
    def validate_headers(cls, v):
        disallowed = ['cookie', 'authorization']
        for header in v.keys():
            if header.lower() in disallowed:
                raise ValueError(f'Header not allowed: {header}')
        return v

class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_types: List[str]
    scan_config: ScanConfig = ScanConfig()

    @validator('scan_types')
    def validate_scan_types(cls, v):
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

    @validator('severity')
    def validate_severity(cls, v):
        allowed = ['critical', 'high', 'medium', 'low', 'info']
        if v.lower() not in allowed:
            raise ValueError(f'Invalid severity: {v}')
        return v.lower()

    @validator('cvss_score')
    def validate_cvss(cls, v):
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

    @validator('schedule_type')
    def validate_schedule_type(cls, v):
        if v not in ['cron', 'interval']:
            raise ValueError('Schedule type must be either cron or interval')
        return v

    @validator('interval_seconds')
    def validate_interval(cls, v, values):
        if values['schedule_type'] == 'interval':
            if v is None:
                raise ValueError('interval_seconds required for interval schedule')
            if v < 3600:  # Minimum 1 hour
                raise ValueError('Interval must be at least 3600 seconds (1 hour)')
        return v

    @validator('cron_expression')
    def validate_cron(cls, v, values):
        if values['schedule_type'] == 'cron' and not v:
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

    @validator('asset_criticality')
    def validate_criticality(cls, v):
        allowed = ['critical', 'high', 'medium', 'low']
        if v.lower() not in allowed:
            raise ValueError(f'Invalid criticality level: {v}')
        return v.lower()

    @validator('data_classification')
    def validate_classification(cls, v):
        allowed = ['public', 'internal', 'confidential', 'restricted']
        if v.lower() not in allowed:
            raise ValueError(f'Invalid data classification: {v}')
        return v.lower()