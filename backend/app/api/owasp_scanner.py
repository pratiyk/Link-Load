"""Clean OWASP scanner API router.

This module exposes endpoints for starting scans, querying progress, listing
scans, exporting reports, and canceling scans. It delegates scanning work to
the `scanner_orchestrator` service and uses `SupabaseClient` for persistence.

Notes:
- The actual ZAP orchestration (starting Zap, talking to the ZAP API, mapping
  alerts to OWASP Top 10, etc.) should live in `services/scanner_orchestrator`.
  This router only validates requests, creates database records, and delegates
  long-running work to the orchestrator via background tasks.
"""

import logging
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, status, Query
from fastapi.responses import FileResponse

from app.core.security import get_current_user_id
from app.models.scan_models import ScanRequest, ScanResult, ScanProgress, Vulnerability
from app.services.scanner_orchestrator import scanner_orchestrator
from app.core.config import settings
from app.database.supabase_client import SupabaseClient
from uuid import UUID

logger = logging.getLogger(__name__)
router = APIRouter(prefix=settings.API_PREFIX, tags=["OWASP Scanner"])

# Initialize DB client
supabase = SupabaseClient()


@router.post("/scan/start", response_model=ScanResult, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(req: ScanRequest, bg: BackgroundTasks, user_id: str = Depends(get_current_user_id)):
    """Start a new scan and return immediately with a scan ID."""
    try:
        scan_id = str(uuid.uuid4())
        record = {
            "scan_id": scan_id,
            "status": "queued",
            "target_url": str(req.target_url),
            "scan_types": req.scan_types,
            "include_low_risk": req.include_low_risk,
            "started_at": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "max_scan_time": req.max_scan_time,
            "scan_config": req.dict(exclude={"target_url", "scan_types", "include_low_risk"})
        }

        supabase.create_scan(record)

        # Run orchestrator in background
        bg.add_task(scanner_orchestrator.run_scan, scan_id, req, user_id)

        return ScanResult(
            scan_id=scan_id,
            status="queued",
            started_at=datetime.utcnow(),
            user_id=user_id,
            target_url=str(req.target_url),
            scan_types=req.scan_types,
        )
    except Exception as e:
        logger.exception("Failed to start scan")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/scan/{scan_id}/status", response_model=ScanProgress)
async def get_scan_progress(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        UUID(scan_id)
        progress = scanner_orchestrator.get_progress(scan_id, user_id)
        if progress is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        return progress
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan ID format")
    except Exception as e:
        logger.exception("Progress retrieval failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        UUID(scan_id)
        result = scanner_orchestrator.get_result(scan_id, user_id)
        if result is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        return result
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan ID format")
    except Exception as e:
        logger.exception("Result retrieval failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/scan/{scan_id}/vulnerabilities", response_model=List[Vulnerability])
async def get_vulns(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        UUID(scan_id)
        result = scanner_orchestrator.get_result(scan_id, user_id)
        if result is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        return result.vulnerabilities
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan ID format")
    except Exception as e:
        logger.exception("Vulnerabilities retrieval failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/scan/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
async def cancel_scan(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        UUID(scan_id)
        ok = scanner_orchestrator.cancel_scan(scan_id, user_id)
        if ok:
            return {"status": "cancellation_requested"}
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found or already completed")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan ID format")
    except Exception as e:
        logger.exception("Scan cancel failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/scans", response_model=List[ScanResult])
async def list_user_scans(status: Optional[str] = Query(None), limit: int = Query(10, ge=1, le=100), offset: int = Query(0, ge=0), user_id: str = Depends(get_current_user_id)):
    try:
        scans = supabase.get_user_scans(user_id, status, limit, offset)
        return scans
    except Exception as e:
        logger.exception("List scans failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/scan/{scan_id}/export")
async def export_scan_report(scan_id: str, format: str = Query("pdf", regex="^(pdf|csv|json)$"), user_id: str = Depends(get_current_user_id)):
    try:
        scan = supabase.fetch_scan(scan_id)
        if not scan or scan.get("user_id") != user_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        report_path = scanner_orchestrator.generate_report(scan_id, format)
        return FileResponse(report_path, media_type="application/octet-stream", filename=f"security-scan-report-{scan_id}.{format}")
    except Exception as e:
        logger.exception("Export failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))