from typing import Dict, List, Optional
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime
import json
import asyncio
from collections import defaultdict

class ScanProgressManager:
    def __init__(self):
        self.active_connections: Dict[str, Dict[str, WebSocket]] = defaultdict(dict)
        self.scan_progress: Dict[str, Dict] = {}
        
    async def connect(self, websocket: WebSocket, scan_id: str, client_id: str):
        """Connect a new WebSocket client"""
        await websocket.accept()
        self.active_connections[scan_id][client_id] = websocket
        
        # Send current progress if available
        if scan_id in self.scan_progress:
            await websocket.send_json(self.scan_progress[scan_id])
    
    def disconnect(self, scan_id: str, client_id: str):
        """Disconnect a WebSocket client"""
        if client_id in self.active_connections[scan_id]:
            del self.active_connections[scan_id][client_id]
            
        if not self.active_connections[scan_id]:
            del self.active_connections[scan_id]
    
    async def broadcast_progress(self, scan_id: str, progress_data: Dict):
        """Send progress update to all connected clients for a scan"""
        if not isinstance(progress_data, dict):
            return
            
        self.scan_progress[scan_id] = {
            "type": "progress",
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": progress_data
        }
        
        if scan_id in self.active_connections:
            dead_clients = []
            for client_id, websocket in self.active_connections[scan_id].items():
                try:
                    await websocket.send_json(self.scan_progress[scan_id])
                except WebSocketDisconnect:
                    dead_clients.append(client_id)
                
            # Clean up disconnected clients
            for client_id in dead_clients:
                self.disconnect(scan_id, client_id)
    
    async def broadcast_finding(self, scan_id: str, finding: Dict):
        """Send new finding to all connected clients for a scan"""
        message = {
            "type": "finding",
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": finding
        }
        
        if scan_id in self.active_connections:
            dead_clients = []
            for client_id, websocket in self.active_connections[scan_id].items():
                try:
                    await websocket.send_json(message)
                except WebSocketDisconnect:
                    dead_clients.append(client_id)
                
            # Clean up disconnected clients
            for client_id in dead_clients:
                self.disconnect(scan_id, client_id)
    
    async def broadcast_completion(self, scan_id: str, summary: Dict):
        """Send scan completion notification to all connected clients"""
        message = {
            "type": "completion",
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": summary
        }
        
        if scan_id in self.active_connections:
            dead_clients = []
            for client_id, websocket in self.active_connections[scan_id].items():
                try:
                    await websocket.send_json(message)
                except WebSocketDisconnect:
                    dead_clients.append(client_id)
                
            # Clean up disconnected clients
            for client_id in dead_clients:
                self.disconnect(scan_id, client_id)
            
            # Clear progress data
            if scan_id in self.scan_progress:
                del self.scan_progress[scan_id]

# Global instance
progress_manager = ScanProgressManager()