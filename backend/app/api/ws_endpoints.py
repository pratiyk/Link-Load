from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from app.api.ws_manager import progress_manager
from app.core.security import get_current_user
from app.database import get_db
from sqlalchemy.orm import Session
import uuid

router = APIRouter()

@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_websocket(
    websocket: WebSocket,
    scan_id: str,
    db: Session = Depends(get_db)
):
    """WebSocket endpoint for real-time scan progress updates"""
    client_id = str(uuid.uuid4())
    
    # Verify scan exists
    from sqlalchemy import text
    scan = db.execute(
        text("SELECT id FROM security_scans WHERE id = :scan_id"),
        {"scan_id": scan_id}
    ).fetchone()
    
    if not scan:
        await websocket.close(code=4004, reason="Scan not found")
        return
    
    try:
        await progress_manager.connect(websocket, scan_id, client_id)
        
        while True:
            # Keep connection alive and handle client messages
            data = await websocket.receive_text()
            
            # Echo back to confirm receipt
            await websocket.send_json({"status": "received", "data": data})
            
    except WebSocketDisconnect:
        progress_manager.disconnect(scan_id, client_id)