"""
Comprehensive Security Scanning API Endpoints
Handles all security scanning operations including OWASP ZAP, Nuclei, and Wapiti
"""
import logging
import uuid
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, HttpUrl, Field
from datetime import datetime, timezone

from app.services.comprehensive_scanner import ComprehensiveScanner
from app.core.security import get_current_user_optional, get_current_user
from app.database.supabase_client import supabase
from app.core.config import settings
from app.services.llm_service import llm_service
from app.core.authorization import (
    verify_scan_ownership,
    require_authenticated_user,
    get_user_id,
    AccessDeniedException,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["Comprehensive Scanning"])

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class ScanOptions(BaseModel):
    """Scan configuration options"""
    enable_ai_analysis: bool = True
    enable_mitre_mapping: bool = True
    include_low_risk: bool = False
    deep_scan: bool = False
    timeout_minutes: int = 30
    business_context: Optional[str] = None
    compliance_frameworks: Optional[List[str]] = None


class StartScanRequest(BaseModel):
    """Request to start a new scan"""
    target_url: HttpUrl = Field(..., description="URL to scan")
    scan_types: List[str] = Field(
        default=["owasp", "nuclei", "wapiti"],
        description="Types of scanners to use: owasp, nuclei, wapiti"
    )
    options: ScanOptions = Field(default_factory=ScanOptions)


class ScanInfo(BaseModel):
    """Information about a scan"""
    scan_id: str
    target_url: str
    status: str
    progress: int
    current_stage: str
    started_at: datetime
    completed_at: Optional[datetime] = None


class VulnerabilityInfo(BaseModel):
    """Information about a vulnerability"""
    id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    location: str
    recommendation: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None


class RiskAssessment(BaseModel):
    """Risk assessment for vulnerabilities"""
    overall_risk_score: float = 0.0
    risk_level: str = "Unknown"
    vulnerability_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    risk_factors: Optional[List[Dict[str, Any]]] = None


class AIAnalysisResult(BaseModel):
    """AI-powered analysis results"""
    title: str
    description: str
    recommendations: List[str]
    remediation_priority: str


class ScanResultsResponse(BaseModel):
    """Complete scan results response"""
    scan_id: str
    target_url: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    vulnerabilities: List[VulnerabilityInfo]
    risk_assessment: RiskAssessment
    mitre_mapping: Optional[List[Dict[str, Any]]] = None
    ai_analysis: Optional[List[AIAnalysisResult]] = None
    remediation_strategies: Optional[Dict[str, Any]] = None
    executive_summary: Optional[str] = None
    # Optional diagnostics when debug=1 is requested
    debug: Optional[Dict[str, Any]] = None


class StartScanResponse(BaseModel):
    """Response for starting a scan"""
    scan_id: str
    message: str = "Scan started successfully"
    status_url: str


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

scanner = ComprehensiveScanner()
active_connections: Dict[str, WebSocket] = {}


# ============================================================================
# API ENDPOINTS
# ============================================================================

@router.post("/comprehensive/start", response_model=StartScanResponse)
async def start_comprehensive_scan(
    request: StartScanRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user_optional)
):
    """
    Start a comprehensive security scan
    
    Orchestrates multiple scanners (OWASP ZAP, Nuclei, Wapiti) for comprehensive
    vulnerability assessment with AI-powered analysis.
    """
    try:
        # Generate unique scan ID
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        
        # Create scan record
        user_id = current_user.id if current_user else "anonymous"
        scan_record = {
            "scan_id": scan_id,
            "user_id": user_id,
            "target_url": str(request.target_url),
            "scan_types": request.scan_types,
            "status": "pending",
            "progress": 0,
            "current_stage": "Initializing",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "options": request.options.dict()
        }
        
        supabase.create_scan(scan_record)
        
        # Start scan in background
        background_tasks.add_task(
            _run_comprehensive_scan,
            scan_id,
            str(request.target_url),
            request.scan_types,
            request.options.dict(),
            user_id  # Use the user_id we already determined above
        )
        
        logger.info(f"Scan {scan_id} initiated for {request.target_url}")
        
        return StartScanResponse(
            scan_id=scan_id,
            status_url=f"{settings.API_PREFIX}/scans/comprehensive/{scan_id}/status"
        )
        
    except Exception as e:
        logger.error(f"Failed to start scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to start scan")


@router.get("/comprehensive/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Get the current status of a scan.
    
    SECURITY: Only the owner of the scan can retrieve its status.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        scan = supabase.fetch_scan(scan_id)
        
        # Verify ownership
        verify_scan_ownership(scan, user_id)
        
        return {
            "scan_id": scan_id,
            "status": scan.get("status"),
            "progress": scan.get("progress", 0),
            "current_stage": scan.get("current_stage", "Unknown"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at")
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching scan status: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching scan status")


def _normalize_vulnerability(v: Dict[str, Any]) -> VulnerabilityInfo:
    """Normalize vulnerability data from various scanner formats to VulnerabilityInfo format"""
    raw_score = v.get("cvss_score") or v.get("cvss") or 0.0
    try:
        cvss_score = float(raw_score)
    except (TypeError, ValueError):
        cvss_score = 0.0

    mitre_techniques = v.get("mitre_techniques") or []
    if isinstance(mitre_techniques, dict):
        mitre_techniques = list(mitre_techniques.values())

    raw_id = v.get("vuln_id") or v.get("vulnerability_id") or v.get("id") or uuid.uuid4().hex[:8]
    if not isinstance(raw_id, str):
        raw_id = str(raw_id)

    return VulnerabilityInfo(
        id=raw_id,
        title=v.get("title") or v.get("name") or "Unknown",
        description=v.get("description") or "",
        severity=(v.get("severity") or "medium").lower(),
        cvss_score=cvss_score,
        location=v.get("location") or v.get("url") or v.get("path") or "",
        recommendation=v.get("recommendation") or v.get("solution") or None,
        mitre_techniques=mitre_techniques
    )


@router.get("/comprehensive/{scan_id}/result", response_model=ScanResultsResponse)
async def get_scan_results(
    scan_id: str,
    debug: Optional[bool] = False,
    current_user = Depends(get_current_user)
):
    """Get the complete results of a scan.
    
    SECURITY: Only the owner of the scan can retrieve its results.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        # Fetch scan
        scan = supabase.fetch_scan(scan_id)
        
        # Verify ownership
        verify_scan_ownership(scan, user_id)
        
        # Fetch vulnerabilities
        vulns = supabase.fetch_vulnerabilities(scan_id)
        
        # Build response
        return ScanResultsResponse(
            scan_id=scan_id,
            target_url=str(scan.get("target_url") or ""),
            status=str(scan.get("status") or "unknown"),
            started_at=scan.get("started_at") or datetime.now(timezone.utc),
            completed_at=scan.get("completed_at"),
            vulnerabilities=[
                _normalize_vulnerability(v)
                for v in vulns
            ],
            risk_assessment=RiskAssessment(
                overall_risk_score=scan.get("risk_score") or scan.get("overall_risk_score") or 0.0,
                risk_level=scan.get("risk_level") or "Unknown",
                vulnerability_count=len(vulns),
                critical_count=scan.get("critical_count") or len([v for v in vulns if (v.get("severity") or "").lower() == "critical"]),
                high_count=scan.get("high_count") or len([v for v in vulns if (v.get("severity") or "").lower() == "high"]),
                medium_count=scan.get("medium_count") or len([v for v in vulns if (v.get("severity") or "").lower() == "medium"]),
                low_count=scan.get("low_count") or len([v for v in vulns if (v.get("severity") or "").lower() == "low"]),
                risk_factors=scan.get("risk_factors")
            ),
            mitre_mapping=scan.get("mitre_mapping"),
            ai_analysis=scan.get("ai_analysis"),
            remediation_strategies=scan.get("remediation_strategies"),
            executive_summary=scan.get("executive_summary"),
            debug=scan.get("scanner_debug") if debug else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching scan results: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching scan results")


@router.get("/comprehensive/list")
async def list_scans(
    skip: int = 0,
    limit: int = 10,
    status: Optional[str] = None,
    current_user = Depends(get_current_user)
):
    """List the current user's scans with optional filtering.
    
    SECURITY: Users can only retrieve their own scans.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        scans = supabase.get_user_scans(user_id, status, limit, skip)
        return {
            "scans": scans,
            "total": len(scans),
            "skip": skip,
            "limit": limit
        }
    except Exception as e:
        logger.error(f"Error listing scans: {str(e)}")
        raise HTTPException(status_code=500, detail="Error listing scans")


@router.get("/comprehensive/{scan_id}/summary")
async def generate_scan_summary(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Generate or return cached executive summary for a scan using Groq LLM.
    
    SECURITY: Only the owner of the scan can retrieve its summary.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        scan = supabase.fetch_scan(scan_id)
        
        # Verify ownership
        verify_scan_ownership(scan, user_id)

        vulnerabilities = supabase.fetch_vulnerabilities(scan_id)

        # Return cached summary if available
        cached_summary = scan.get("executive_summary")
        if cached_summary:
            return {
                "scan_id": scan_id,
                "summary": cached_summary,
                "cached": True
            }

        risk_score = scan.get("risk_score") or scan.get("overall_risk_score") or 0.0
        try:
            risk_score_value = float(risk_score)
        except (TypeError, ValueError):
            risk_score_value = 0.0

        risk_level = scan.get("risk_level") or "Unknown"

        summary_text = await llm_service.generate_executive_summary(
            vulnerabilities,
            risk_score_value,
            risk_level
        )

        if summary_text:
            supabase.update_scan(scan_id, {"executive_summary": summary_text})

        return {
            "scan_id": scan_id,
            "summary": summary_text,
            "cached": False
        }

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"LLM provider unavailable for summary: {e}")
        raise HTTPException(status_code=503, detail="LLM provider unavailable for summary generation")
    except Exception as e:
        logger.error(f"Failed to generate scan summary: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to generate scan summary")


@router.get("/comprehensive/{scan_id}")
async def get_scan_result_redirect(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Alias for get_scan_results for backward compatibility.
    
    SECURITY: Enforces user ownership via get_scan_results.
    """
    return await get_scan_results(scan_id, debug=False, current_user=current_user)


@router.websocket("/ws/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan progress updates
    
    Sends live updates about scan progress, stages, and final results.
    """
    await websocket.accept()
    active_connections[scan_id] = websocket
    
    try:
        while True:
            # Fetch current scan status
            scan = supabase.fetch_scan(scan_id)
            
            if scan:
                await websocket.send_json({
                    "type": "progress",
                    "status": {
                        "scan_id": scan_id,
                        "progress": scan.get("progress", 0),
                        "current_stage": scan.get("current_stage"),
                        "status": scan.get("status")
                    }
                })
                
                # Send results if scan is complete
                if scan.get("status") == "completed":
                    vulns = supabase.fetch_vulnerabilities(scan_id)
                    await websocket.send_json({
                        "type": "result",
                        "results": {
                            "scan_id": scan_id,
                            "status": "completed",
                            "vulnerabilities": vulns,
                            "risk_score": scan.get("risk_score"),
                            "risk_level": scan.get("risk_level")
                        }
                    })
                    break
            
            # Wait before next update
            import asyncio
            await asyncio.sleep(2)
            
    except WebSocketDisconnect:
        del active_connections[scan_id]
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {str(e)}")
        del active_connections[scan_id]
        try:
            await websocket.close(code=1000)
        except:
            pass


@router.post("/comprehensive/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Cancel an in-progress scan.
    
    SECURITY: Only the owner of the scan can cancel it.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        scan = supabase.fetch_scan(scan_id)
        
        # Verify ownership
        verify_scan_ownership(scan, user_id)
        
        # Update status
        supabase.update_scan(scan_id, {"status": "cancelled"})
        
        return {"message": "Scan cancelled successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Error cancelling scan")


# ============================================================================
# BACKGROUND TASKS
# ============================================================================

async def _run_comprehensive_scan(
    scan_id: str,
    target_url: str,
    scan_types: List[str],
    options: Dict[str, Any],
    user_id: str
):
    """Background task to execute comprehensive scan"""
    try:
        logger.info(f"Starting comprehensive scan {scan_id} for {target_url}")
        
        # Initialize and run scan
        await scanner.start_scan(scan_id, target_url, scan_types, options)
        
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}", exc_info=True)
        try:
            supabase.update_scan(scan_id, {
                "status": "failed",
                "error": str(e),
                "completed_at": datetime.now(timezone.utc).isoformat()
            })
        except Exception as update_error:
            logger.error(f"Failed to update scan status: {update_error}")
