import logging
from fastapi import WebSocket, APIRouter
from app.services.scanner_orchestrator import scanner_orchestrator
from app.core.security import get_current_user_ws

router = APIRouter()
logger = logging.getLogger(__name__)

@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    
    # Authenticate user
    user_id = await get_current_user_ws(websocket)
    if not user_id:
        await websocket.close(code=1008)
        return
    
    # Verify scan ownership
    scan = supabase.fetch_scan(scan_id)
    if not scan or scan.get("user_id") != user_id:
        await websocket.close(code=1008)
        return
    
    # Subscribe to scan updates
    def send_update(data):
        asyncio.run(websocket.send_json(data))
    
    scanner_orchestrator.subscribe(scan_id, send_update)
    
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except Exception as e:
        logger.info(f"WebSocket disconnected: {str(e)}")
    finally:
        scanner_orchestrator.unsubscribe(scan_id, send_update)