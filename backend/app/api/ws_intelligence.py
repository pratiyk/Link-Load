"""
FastAPI WebSocket endpoints for real-time threat intelligence.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from app.core.security import get_current_user_id
from app.database import get_db
from sqlalchemy.orm import Session
from app.services.intelligence_mapping.realtime_intel import RealTimeIntelligence
from typing import Dict, Any
import logging

async def verify_token(token: str) -> str:
    """Verify WebSocket token and return client ID"""
    try:
        user_id = get_current_user_id(token)
        return str(user_id) if user_id else None
    except Exception:
        return None

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/intelligence/ws", tags=["intelligence"])

intel_service: RealTimeIntelligence = None

def get_intel_service(db: Session = Depends(get_db)) -> RealTimeIntelligence:
    """Get or create intelligence service singleton."""
    global intel_service
    if intel_service is None:
        intel_service = RealTimeIntelligence(db)
    return intel_service

@router.websocket("/stream")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str,
    intel_service: RealTimeIntelligence = Depends(get_intel_service)
):
    """WebSocket endpoint for real-time threat intelligence streaming."""
    try:
        await intel_service.start_streaming(websocket, token)
    except WebSocketDisconnect:
        logger.info("Client disconnected from intelligence stream")
    except Exception as e:
        logger.error(f"Error in WebSocket connection: {e}")
        await websocket.close(code=1011)  # Internal error

@router.websocket("/query")
async def query_endpoint(
    websocket: WebSocket,
    token: str,
    intel_service: RealTimeIntelligence = Depends(get_intel_service)
):
    """WebSocket endpoint for querying threat intelligence."""
    try:
        # Verify token and get client ID
        client_id = await verify_token(token)
        if not client_id:
            await websocket.close(code=4001)
            return
            
        await websocket.accept()
        
        while True:
            # Receive query
            query = await websocket.receive_json()
            
            # Process query
            results = await intel_service._handle_query(query)
            
            # Send results
            await websocket.send_json({
                "type": "query_result",
                "data": results
            })
            
    except WebSocketDisconnect:
        logger.info("Client disconnected from query endpoint")
    except Exception as e:
        logger.error(f"Error in query endpoint: {e}")
        await websocket.close(code=1011)