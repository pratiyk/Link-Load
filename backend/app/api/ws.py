import logging
import asyncio
from typing import Optional
from fastapi import WebSocket, APIRouter, WebSocketDisconnect
from app.services.scanner_orchestrator import scanner_orchestrator
from app.core.security import get_current_user_ws
from app.database.supabase_client import supabase

router = APIRouter()
logger = logging.getLogger(__name__)

@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan updates"""
    try:
        await websocket.accept()
        
        # Authenticate user
        user_id = await get_current_user_ws(websocket)
        if not user_id:
            logger.warning(f"Unauthorized WebSocket connection attempt for scan {scan_id}")
            await websocket.close(code=1008)
            return
        
        # Verify scan ownership
        scan = supabase.fetch_scan(scan_id)
        if not scan or scan.get("user_id") != user_id:
            logger.warning(f"Unauthorized scan access attempt: {scan_id} by user {user_id}")
            await websocket.close(code=1008)
            return
        
        # Subscribe to scan updates
        async def send_update(data):
            try:
                await websocket.send_json(data)
            except WebSocketDisconnect:
                logger.info(f"WebSocket disconnected while sending update for scan {scan_id}")
            except Exception as e:
                logger.error(f"Error sending WebSocket update: {str(e)}")
        
        scanner_orchestrator.subscribe(scan_id, send_update)
        
        ping_interval = 30  # seconds
        last_ping = asyncio.get_event_loop().time()
        
        while True:
            try:
                # Implement ping/pong for connection health
                current_time = asyncio.get_event_loop().time()
                if current_time - last_ping >= ping_interval:
                    await websocket.send_json({"type": "ping"})
                    last_ping = current_time
                
                # Wait for messages with timeout
                data = await asyncio.wait_for(websocket.receive_text(), timeout=ping_interval)
                if data == "pong":
                    continue
                
            except asyncio.TimeoutError:
                # No message received, continue to send ping
                continue
            except WebSocketDisconnect:
                logger.info(f"WebSocket disconnected for scan {scan_id}")
                break
            except Exception as e:
                logger.error(f"WebSocket error for scan {scan_id}: {str(e)}")
                break
                
    except Exception as e:
        logger.error(f"Error in WebSocket connection: {str(e)}")
    finally:
        try:
            scanner_orchestrator.unsubscribe(scan_id, send_update)
            await websocket.close()
        except Exception as e:
            logger.error(f"Error during WebSocket cleanup: {str(e)}")