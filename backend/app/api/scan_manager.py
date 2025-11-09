from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel

from app.database import get_db
from app.services.scanners.scanner_orchestrator import ScannerOrchestrator
from app.core.security import get_current_user
from app.models.user import User
from app.utils.datetime_utils import utc_now_naive
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
    """Response with scan details"""
    id: str
    user_id: str
    target_url: str
    scan_types: List[str]
    status: str
    scan_config: Dict[str, Any]
    started_at: datetime
    completed_at: Optional[datetime]
    progress: Optional[ScanProgress]
    summary: Optional[ScanSummary]
    errors: Optional[List[str]]
    
    class Config:
        from_attributes = True
import uuid

router = APIRouter()
orchestrator = ScannerOrchestrator()

@router.post("/scans", response_model=ScanResponse)
async def initiate_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start a new security scan"""
    scan_id = str(uuid.uuid4())
    
    # Create scan record
    scan = {
        "id": scan_id,
        "user_id": current_user.id,
        "target_url": request.target_url,
        "scan_types": request.scan_types,
        "status": "pending",
        "scan_config": request.scan_config.dict(),
        "started_at": utc_now_naive()
    }
    
    # Add to database
    from sqlalchemy import text
    db.execute(
        text("""INSERT INTO security_scans (id, user_id, target_url, scan_types, status, 
        scan_config, started_at) VALUES (:id, :user_id, :target_url, :scan_types,
        :status, :scan_config, :started_at)""")
        .bindparams(**scan)
    )
    db.commit()
    
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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get status of a specific scan"""
    stmt = text(
        """SELECT * FROM security_scans 
        WHERE id = :scan_id AND user_id = :user_id"""
    )
    scan = db.execute(
        stmt.bindparams(scan_id=scan_id, user_id=current_user.id)
    ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanResponse(**dict(scan))

@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 10,
    offset: int = 0
):
    """List all scans for the current user"""
    stmt = text(
        """SELECT * FROM security_scans 
        WHERE user_id = :user_id 
        ORDER BY started_at DESC 
        LIMIT :limit OFFSET :offset"""
    )
    scans = db.execute(
        stmt.bindparams(
            user_id=current_user.id,
            limit=limit,
            offset=offset
        )
    ).fetchall()
    
    return [ScanResponse(**dict(scan)) for scan in scans]

@router.delete("/scans/{scan_id}")
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cancel an ongoing scan"""
    stmt = text(
        """SELECT status FROM security_scans 
        WHERE id = :scan_id AND user_id = :user_id"""
    )
    scan = db.execute(
        stmt.bindparams(scan_id=scan_id, user_id=current_user.id)
    ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status not in ["pending", "running"]:
        raise HTTPException(status_code=400, detail="Scan cannot be cancelled")
    
    # Stop the scan
    orchestrator.stop_scan(scan_id)
    
    # Update status
    stmt = text(
        """UPDATE security_scans 
        SET status = 'cancelled', completed_at = :completed_at 
        WHERE id = :scan_id"""
    )
    db.execute(
        stmt.bindparams(
            scan_id=scan_id,
            completed_at=utc_now_naive()
        )
    )
    db.commit()
    
    return {"status": "cancelled"}

@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get vulnerability findings for a specific scan"""
    # Verify scan ownership
    stmt = text(
        """SELECT id FROM security_scans 
        WHERE id = :scan_id AND user_id = :user_id"""
    )
    scan = db.execute(
        stmt.bindparams(scan_id=scan_id, user_id=current_user.id)
    ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Build query
    query = """SELECT * FROM vulnerability_findings 
             WHERE scan_id = :scan_id"""
    if severity:
        query += " AND severity = :severity"

    stmt = text(query)
    params = {"scan_id": scan_id}
    if severity:
        params["severity"] = severity
    
    findings = db.execute(stmt.bindparams(**params)).fetchall()
    return [dict(finding) for finding in findings]