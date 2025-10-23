"""API routes for comprehensive security scanning."""
from fastapi import APIRouter, WebSocket, HTTPException, Depends, BackgroundTasks
from typing import List, Optional
from pydantic import BaseModel, HttpUrl
from datetime import datetime

from app.services.comprehensive_scanner import ComprehensiveScanner
from app.core.security import get_current_user
from app.models.vulnerability_models import ScanResult
from app.core.websocket import WebSocketManager

router = APIRouter(prefix="/api/v1/scan", tags=["Security Scanning"])
ws_manager = WebSocketManager()
scanner = ComprehensiveScanner()

class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_types: List[str]
    options: dict = {}

class ScanResponse(BaseModel):
    scan_id: str
    message: str = "Scan started successfully"

@router.post("/start", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user)
):
    """Start a comprehensive security scan."""
    try:
        scan_id = await scanner.start_scan(
            str(request.target_url),
            request.scan_types,
            request.options
        )
        return {"scan_id": scan_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{scan_id}")
async def get_scan_results(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Get the results of a completed scan."""
    results = await scanner.get_scan_results(scan_id)
    if not results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return results

@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Get the current status of a scan."""
    status = await scanner.get_scan_status(scan_id)
    if status["status"] == "not_found":
        raise HTTPException(status_code=404, detail="Scan not found")
    return status

@router.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan updates."""
    await ws_manager.connect(websocket, scan_id)
    try:
        while True:
            status = await scanner.get_scan_status(scan_id)
            if status["status"] == "completed":
                results = await scanner.get_scan_results(scan_id)
                await ws_manager.send_message(scan_id, {
                    "type": "result",
                    "results": results
                })
                break
            await ws_manager.send_message(scan_id, {
                "type": "progress",
                "status": status
            })
            await asyncio.sleep(2)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await ws_manager.disconnect(websocket, scan_id)