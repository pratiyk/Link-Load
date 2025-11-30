import logging
import asyncio
from typing import Optional
from fastapi import WebSocket, APIRouter, WebSocketDisconnect
from app.services.scanner_orchestrator import scanner_orchestrator
from app.core.security import security_manager
from app.database.supabase_client import supabase

router = APIRouter()
logger = logging.getLogger(__name__)


def _authenticate_ws_token(websocket: WebSocket) -> Optional[str]:
    """Authenticate WebSocket connection using token from query params.
    
    Returns user_id if valid, None otherwise. Does NOT close the websocket.
    """
    try:
        token = websocket.query_params.get("token")
        if not token:
            logger.debug("No token provided in WebSocket query params")
            return None
        
        payload = security_manager.verify_token(token)
        if not payload:
            logger.debug("Invalid or expired WebSocket token")
            return None
            
        return payload.get("sub")
    except Exception as e:
        logger.debug(f"WebSocket token authentication error: {e}")
        return None


@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan updates"""
    send_update = None
    connected = False
    
    try:
        # Accept the connection first
        await websocket.accept()
        connected = True
        logger.info(f"WebSocket connection accepted for scan {scan_id}")
        
        # Authenticate user (don't close in auth function)
        user_id = _authenticate_ws_token(websocket)
        if not user_id:
            logger.warning(f"Unauthorized WebSocket connection attempt for scan {scan_id}")
            await websocket.send_json({"type": "error", "message": "Authentication failed"})
            await websocket.close(code=1008)
            return
        
        # Verify scan ownership
        scan = supabase.fetch_scan(scan_id)
        if not scan:
            logger.warning(f"Scan not found: {scan_id}")
            await websocket.send_json({"type": "error", "message": "Scan not found"})
            await websocket.close(code=1008)
            return
            
        if scan.get("user_id") != user_id:
            logger.warning(f"Unauthorized scan access attempt: {scan_id} by user {user_id}")
            await websocket.send_json({"type": "error", "message": "Access denied"})
            await websocket.close(code=1008)
            return
        
        # Send initial status immediately
        initial_status = {
            "type": "progress",
            "status": {
                "scan_id": scan_id,
                "status": scan.get("status", "pending"),
                "progress": scan.get("progress", 0),
                "current_stage": scan.get("current_stage", "Initializing")
            }
        }
        await websocket.send_json(initial_status)
        logger.info(f"Sent initial status for scan {scan_id}: {scan.get('status')}")
        
        # If scan is already completed, send results immediately
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
            logger.info(f"Scan {scan_id} already completed, sent results")
            await websocket.close(code=1000)
            return
        
        # Subscribe to scan updates
        async def send_update(data):
            try:
                await websocket.send_json(data)
                logger.debug(f"Sent WebSocket update for scan {scan_id}: {data.get('type')}")
            except WebSocketDisconnect:
                logger.info(f"WebSocket disconnected while sending update for scan {scan_id}")
            except Exception as e:
                logger.error(f"Error sending WebSocket update: {str(e)}")
        
        scanner_orchestrator.subscribe(scan_id, send_update)
        logger.info(f"Subscribed to updates for scan {scan_id}")
        
        ping_interval = 30  # seconds
        poll_interval = 3   # seconds - poll database for status updates
        last_ping = asyncio.get_event_loop().time()
        last_poll = asyncio.get_event_loop().time()
        
        while True:
            try:
                current_time = asyncio.get_event_loop().time()
                
                # Send ping for connection health
                if current_time - last_ping >= ping_interval:
                    await websocket.send_json({"type": "ping"})
                    last_ping = current_time
                
                # Poll database for status updates (backup mechanism)
                if current_time - last_poll >= poll_interval:
                    current_scan = supabase.fetch_scan(scan_id)
                    if current_scan:
                        scan_status = current_scan.get("status")
                        
                        # Send progress update
                        await websocket.send_json({
                            "type": "progress",
                            "status": {
                                "scan_id": scan_id,
                                "status": scan_status,
                                "progress": current_scan.get("progress", 0),
                                "current_stage": current_scan.get("current_stage", "Processing")
                            }
                        })
                        
                        # If completed, send results and close
                        if scan_status == "completed":
                            vulns = supabase.fetch_vulnerabilities(scan_id)
                            await websocket.send_json({
                                "type": "result",
                                "results": {
                                    "scan_id": scan_id,
                                    "status": "completed",
                                    "vulnerabilities": vulns,
                                    "risk_score": current_scan.get("risk_score"),
                                    "risk_level": current_scan.get("risk_level")
                                }
                            })
                            logger.info(f"Scan {scan_id} completed, closing WebSocket")
                            break
                        elif scan_status in ["failed", "cancelled"]:
                            await websocket.send_json({
                                "type": "error",
                                "message": f"Scan {scan_status}"
                            })
                            logger.info(f"Scan {scan_id} {scan_status}, closing WebSocket")
                            break
                    
                    last_poll = current_time
                
                # Wait for client messages with short timeout
                try:
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
                    if data == "pong":
                        continue
                except asyncio.TimeoutError:
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
            if send_update:
                scanner_orchestrator.unsubscribe(scan_id, send_update)
            if connected:
                await websocket.close()
        except Exception as e:
            logger.debug(f"Error during WebSocket cleanup: {str(e)}")