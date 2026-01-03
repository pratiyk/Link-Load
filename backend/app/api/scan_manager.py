from typing import Any, Dict, List, Optional
import logging

from fastapi import APIRouter, Depends, HTTPException, WebSocket, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel

from app.database.supabase_client import supabase
from app.services.scanners.scanner_orchestrator import ScannerOrchestrator
from app.core.security import get_current_user
from app.models.user import User
from app.utils.datetime_utils import utc_now_naive
from app.core.logging_config import get_business_logger_name
from datetime import datetime

class ScanConfig(BaseModel):
    """Configuration options for a security scan"""
    scan_depth: str = "normal"  # normal, quick, deep
    concurrent_requests: int = 10
    request_delay: float = 0.1
    auth_required: bool = False
    auth_config: Optional[Dict[str, str]] = None
    excluded_paths: List[str] = []
    custom_headers: Dict[str, str] = {}
    scan_timeout: int = 3600  # seconds

class ScanRequest(BaseModel):
    """Request to start a new security scan"""
    target_url: str
    scan_types: List[str]  # zap, nuclei, wapiti
    scan_config: ScanConfig = ScanConfig()

class ScanProgress(BaseModel):
    """Progress information for an ongoing scan"""
    scan_id: str
    current_step: str
    progress_percentage: float
    estimated_time_remaining: Optional[int]
    scanned_urls: int = 0
    total_urls: int = 0
    vulnerabilities_found: int = 0
    last_updated: datetime

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

class ScanResponse(BaseModel):
    scan_id: str
    user_id: str
    target_url: str
    scan_types: List[str]
    status: str
    options: dict = {}
    started_at: datetime
    completed_at: Optional[datetime] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    # Add more fields as needed from owasp_scans
import uuid

router = APIRouter()
orchestrator = ScannerOrchestrator()
logger = logging.getLogger(__name__)
business_logger = logging.getLogger(get_business_logger_name())

@router.post("/scans", response_model=ScanResponse)
async def initiate_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    # db: Session = Depends(get_db)  # No longer needed for Supabase endpoints
):
    """Start a new security scan"""
    scan_id = str(uuid.uuid4())
    
    # Create scan record
    user_id = current_user["id"] if isinstance(current_user, dict) else current_user.id
    scan = {
        "id": scan_id,
        "user_id": user_id,
        "target_url": request.target_url,
        "scan_types": request.scan_types,
        "status": "pending",
        "scan_config": request.scan_config.dict(),
        "started_at": utc_now_naive()
    }
    business_logger.info(
        "SCAN_INITIATED | user_id=%s | scan_id=%s | target=%s | types=%s",
        str(user_id),
        scan_id,
        request.target_url,
        ",".join(request.scan_types),
    )
    # Add to Supabase
    from app.database.supabase_client import supabase
    supabase.create_scan({
        "scan_id": scan_id,
        "user_id": str(user_id),
        "target_url": request.target_url,
        "scan_types": request.scan_types,
        "status": "pending",
        "options": request.scan_config.dict(),
        "started_at": scan["started_at"],
    })
    
    # Start scan in background
    background_tasks.add_task(
        orchestrator.run_scan,
        scan_id=scan_id,
        target=request.target_url,
        scan_types=request.scan_types,
        config=request.scan_config.dict()
    )
    
    return ScanResponse(**scan)

@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get status of a specific scan from Supabase owasp_scans table"""
    user_id = current_user["id"] if isinstance(current_user, dict) else current_user.id
    scan = supabase.fetch_scan(scan_id, user_id=str(user_id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    business_logger.info(
        "SCAN_STATUS_REQUEST | user_id=%s | scan_id=%s | status=%s",
        str(user_id),
        scan_id,
        scan.get("status"),
    )
    return ScanResponse(**scan)

@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(
    current_user: User = Depends(get_current_user),
    limit: int = 10,
    offset: int = 0
):
    """List all scans for the current user from Supabase owasp_scans table"""
    user_id = current_user["id"] if isinstance(current_user, dict) else current_user.id
    scans = supabase.get_user_scans(str(user_id), limit=limit, offset=offset)
    business_logger.info(
        "SCAN_LIST_REQUEST | user_id=%s | count=%s | limit=%s | offset=%s",
        str(user_id),
        len(scans),
        limit,
        offset,
    )
    return [ScanResponse(**scan) for scan in scans]

@router.delete("/scans/{scan_id}")
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user)
):
    """Cancel an ongoing scan (Supabase logic not yet implemented)"""
    raise NotImplementedError("Supabase-based scan cancellation not yet implemented.")

@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Get vulnerability findings for a specific scan (Supabase logic not yet implemented)"""
    raise NotImplementedError("Supabase-based findings retrieval not yet implemented.")