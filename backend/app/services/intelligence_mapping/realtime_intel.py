"""WebSocket-based real-time threat intelligence streaming service."""
from typing import Dict, Any, Optional, List, Set, cast
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
from datetime import datetime, timedelta
import logging
from collections import defaultdict

from app.core.security import verify_token
from app.models.threat_intel_models import ThreatIntelligence
from sqlalchemy.orm import Session
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)

class ThreatIntelManager:
    """
    Manages real-time threat intelligence streaming and client connections.
    """
    
    def __init__(self):
        """Initialize the threat intelligence manager."""
        self.active_connections: Dict[str, List[WebSocket]] = defaultdict(list)
        self.intelligence_buffer: List[Dict[str, Any]] = []
        self.buffer_size = 1000
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, client_id: str):
        """Connect a new client."""
        await websocket.accept()
        async with self._lock:
            self.active_connections[client_id].append(websocket)
        logger.info(f"Client {client_id} connected to threat intel stream")

    async def disconnect(self, websocket: WebSocket, client_id: str):
        """Disconnect a client."""
        async with self._lock:
            if client_id in self.active_connections:
                self.active_connections[client_id].remove(websocket)
                if not self.active_connections[client_id]:
                    del self.active_connections[client_id]
        logger.info(f"Client {client_id} disconnected from threat intel stream")

    async def broadcast_intelligence(
        self,
        intel_data: Dict[str, Any],
        target_clients: Optional[List[str]] = None
    ):
        """Broadcast threat intelligence to connected clients."""
        timestamp = utc_now().isoformat()
        payload = dict(intel_data)
        payload.setdefault("timestamp", timestamp)
        message = {
            "type": "threat_intel",
            "data": payload,
            "timestamp": timestamp
        }
        
        # Add to buffer
        self.intelligence_buffer.append(payload)
        if len(self.intelligence_buffer) > self.buffer_size:
            self.intelligence_buffer.pop(0)
        
        # Broadcast to specific clients or all
        clients_to_remove = []
        async with self._lock:
            for client_id, connections in self.active_connections.items():
                if target_clients and client_id not in target_clients:
                    continue
                    
                dead_connections = []
                for websocket in connections:
                    try:
                        await websocket.send_json(message)
                    except WebSocketDisconnect:
                        dead_connections.append(websocket)
                    except Exception as e:
                        logger.error(f"Error sending to client {client_id}: {e}")
                        dead_connections.append(websocket)
                
                # Clean up dead connections
                for dead in dead_connections:
                    connections.remove(dead)
                if not connections:
                    clients_to_remove.append(client_id)
            
            # Remove empty client entries
            for client_id in clients_to_remove:
                del self.active_connections[client_id]

    async def get_recent_intelligence(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent threat intelligence from buffer."""
        return self.intelligence_buffer[-limit:]

class RealTimeIntelligence:
    """
    Real-time threat intelligence processing and streaming service.
    """
    
    def __init__(self, db: Session):
        """Initialize the real-time intelligence service."""
        self.db = db
        self.intel_manager = ThreatIntelManager()
        self.processing_tasks: Dict[str, asyncio.Task] = {}
        self.subscriptions: Dict[str, Set[str]] = defaultdict(set)
        
    async def start_streaming(self, websocket: WebSocket, token: str):
        """Start streaming threat intelligence to a client."""
        client_id: Optional[str] = None
        try:
            # Verify client token
            client_id = await verify_token(token)
            if not client_id:
                await websocket.close(code=4001)
                return
                
            # Connect client
            await self.intel_manager.connect(websocket, client_id)
            
            # Send initial data
            recent_intel = await self.intel_manager.get_recent_intelligence()
            for intel in recent_intel:
                await websocket.send_json({
                    "type": "historical",
                    "data": intel,
                    "timestamp": utc_now().isoformat()
                })
            
            # Start receiving messages
            while True:
                try:
                    message = await websocket.receive_json()
                    await self._handle_client_message(message, client_id)
                except WebSocketDisconnect:
                    break
                except Exception as e:
                    logger.error(f"Error handling client message: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Error in threat intel streaming: {e}")
        finally:
            if client_id:
                await self.intel_manager.disconnect(websocket, client_id)
                self.subscriptions.pop(client_id, None)

    async def process_new_intelligence(
        self,
        intel_data: Dict[str, Any],
        source: str
    ):
        """Process and broadcast new threat intelligence."""
        try:
            # Store in database
            threat_type = intel_data.get("type")
            if not threat_type:
                logger.warning("Skipping intelligence without threat type: %s", intel_data)
                return

            intel = ThreatIntelligence(
                source=source,
                threat_type=threat_type,
                name=intel_data.get("name"),
                description=intel_data.get("description"),
                confidence_score=intel_data.get("confidence", 0.5),
                severity=intel_data.get("severity", 0.5),
                indicators=intel_data.get("indicators", {}),
                references=intel_data.get("references", [])
            )
            self.db.add(intel)
            self.db.flush()
            self.db.refresh(intel)

            # Determine interested clients based on subscriptions
            threat_type_value = cast(Optional[str], intel.threat_type)
            target_clients = self._subscribers_for_type(threat_type_value)

            # Broadcast to relevant clients
            await self.intel_manager.broadcast_intelligence({
                "id": intel.id,
                "source": intel.source,
                "type": intel.threat_type,
                "name": intel.name,
                "description": intel.description,
                "confidence": intel.confidence_score,
                "severity": intel.severity,
                "indicators": intel.indicators,
                "timestamp": utc_now().isoformat()
            }, target_clients=target_clients or None)
            
            # Trigger model retraining if needed
            await self._check_model_retraining(intel_data)
            
        except Exception as e:
            logger.error(f"Error processing new intelligence: {e}")
            self.db.rollback()

    async def _handle_client_message(
        self,
        message: Dict[str, Any],
        client_id: str
    ):
        """Handle incoming messages from clients."""
        msg_type = message.get("type")
        
        if msg_type == "subscribe":
            # Handle subscription to specific intel types
            intel_types = message.get("intel_types", [])
            await self._handle_subscription(client_id, intel_types)
            
        elif msg_type == "query":
            # Handle intelligence queries
            query_data = message.get("query", {})
            results = await self._handle_query(query_data)
            
            # Send results back to client
            for conn in self.intel_manager.active_connections.get(client_id, []):
                try:
                    await conn.send_json({
                        "type": "query_result",
                        "data": results,
                        "timestamp": utc_now().isoformat()
                    })
                except Exception as e:
                    logger.error(f"Error sending query results: {e}")

    async def _handle_subscription(
        self,
        client_id: str,
        intel_types: List[str]
    ):
        """Handle client subscription to specific intelligence types."""
        normalized = {t.lower() for t in intel_types if isinstance(t, str)}
        if normalized:
            self.subscriptions[client_id] = normalized
        else:
            # Empty list implies subscribe to all
            self.subscriptions.pop(client_id, None)

    async def _handle_query(
        self,
        query_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Handle intelligence queries from clients."""
        query = self.db.query(ThreatIntelligence)

        threat_type = query_data.get("type")
        if threat_type:
            query = query.filter(ThreatIntelligence.threat_type == threat_type)

        timeframe = query_data.get("timeframe")
        cutoff = self._timeframe_cutoff(timeframe) if timeframe else None
        if cutoff is not None:
            query = query.filter(ThreatIntelligence.created_at >= cutoff)

        results = query.order_by(ThreatIntelligence.created_at.desc()).limit(100).all()

        return [
            {
                "id": item.id,
                "source": item.source,
                "type": item.threat_type,
                "name": item.name,
                "description": item.description,
                "confidence": item.confidence_score,
                "severity": item.severity,
                "indicators": item.indicators,
                "timestamp": (item.created_at or utc_now()).isoformat(),
            }
            for item in results
        ]

    async def _check_model_retraining(self, intel_data: Dict[str, Any]):
        """Check if model retraining is needed based on new intelligence."""
        # Implementation depends on ML pipeline requirements
        pass

    def _timeframe_cutoff(self, timeframe: str) -> Optional[datetime]:
        """Convert timeframe strings like '24h' or '7d' into UTC cutoffs."""
        if not timeframe:
            return None

        try:
            value = int(timeframe[:-1])
        except (TypeError, ValueError):
            return None

        unit = timeframe[-1].lower()
        if unit == "h":
            delta = timedelta(hours=value)
        elif unit == "d":
            delta = timedelta(days=value)
        else:
            return None

        return utc_now() - delta

    def _subscribers_for_type(self, threat_type: Optional[str]) -> List[str]:
        """Determine which clients should receive a threat type broadcast."""
        if not threat_type:
            return list(self.intel_manager.active_connections.keys())

        normalized = threat_type.lower()
        recipients: List[str] = []
        for client_id, types in self.subscriptions.items():
            if not types or normalized in types:
                recipients.append(client_id)
        return recipients