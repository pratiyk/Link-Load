"""Integration tests for real-time threat intelligence updates."""
import pytest
from app.services.intelligence_mapping.realtime_intel import (
    RealTimeIntelligence,
    ThreatIntelManager
)
import asyncio
from fastapi import WebSocket
from typing import Dict, Any
import json
from datetime import datetime, timedelta, timezone

@pytest.mark.asyncio
async def test_client_connection(realtime_intel, mock_websocket):
    """Test WebSocket client connection and disconnection."""
    # Test connection
    test_token = "valid_test_token"
    await realtime_intel.start_streaming(mock_websocket, test_token)
    
    # Verify connection in manager
    assert len(realtime_intel.intel_manager.active_connections) > 0
    
    # Test disconnection
    await realtime_intel.intel_manager.disconnect(mock_websocket, "test_client")
    assert "test_client" not in realtime_intel.intel_manager.active_connections

@pytest.mark.asyncio
async def test_intelligence_broadcasting(realtime_intel, mock_websocket, db_session):
    """Test broadcasting threat intelligence to connected clients."""
    # Connect test client
    test_token = "valid_test_token"
    await realtime_intel.start_streaming(mock_websocket, test_token)
    
    # Create test intelligence
    test_intel = {
        "type": "malware",
        "name": "TestMalware",
        "description": "Test malware description",
        "confidence": 0.8,
        "severity": 0.9,
        "indicators": {
            "hashes": ["abc123"],
            "ips": ["1.2.3.4"]
        }
    }
    
    # Broadcast intelligence
    await realtime_intel.process_new_intelligence(test_intel, "test_source")
    
    # Verify intelligence was stored and broadcast
    assert len(realtime_intel.intel_manager.intelligence_buffer) > 0
    last_intel = realtime_intel.intel_manager.intelligence_buffer[-1]
    assert last_intel["name"] == "TestMalware"

@pytest.mark.asyncio
async def test_real_time_updates(realtime_intel, mock_websocket):
    """Test real-time intelligence updates and subscriptions."""
    # Connect client with subscriptions
    await realtime_intel.start_streaming(mock_websocket, "valid_test_token")
    
    # Send subscription message
    await realtime_intel._handle_client_message(
        {
            "type": "subscribe",
            "intel_types": ["malware", "ransomware"]
        },
        "test_client"
    )
    
    # Send test intelligence updates
    test_updates = [
        {
            "type": "malware",
            "name": "Test1",
            "severity": 0.8
        },
        {
            "type": "ransomware",
            "name": "Test2",
            "severity": 0.9
        },
        {
            "type": "phishing",
            "name": "Test3",
            "severity": 0.7
        }
    ]
    
    for update in test_updates:
        await realtime_intel.process_new_intelligence(update, "test_source")
    
    # Verify filtered updates in buffer
    buffer = realtime_intel.intel_manager.intelligence_buffer
    assert len([i for i in buffer if i["type"] in ["malware", "ransomware"]]) == 2

@pytest.mark.asyncio
async def test_intelligence_query(realtime_intel, mock_websocket, db_session):
    """Test querying historical intelligence data."""
    # Add test data
    test_data = [
        {
            "type": "malware",
            "name": f"Test{i}",
            "timestamp": datetime.now(timezone.utc) - timedelta(hours=i)
        }
        for i in range(5)
    ]
    
    for data in test_data:
        await realtime_intel.process_new_intelligence(data, "test_source")
    
    # Test query
    query_result = await realtime_intel._handle_query({
        "type": "malware",
        "timeframe": "24h"
    })
    
    assert len(query_result) > 0
    assert all(i["type"] == "malware" for i in query_result)

@pytest.mark.asyncio
async def test_error_handling(realtime_intel, mock_websocket):
    """Test error handling in real-time intelligence processing."""
    # Test invalid token
    await realtime_intel.start_streaming(mock_websocket, "invalid_token")
    
    # Test invalid message format
    await realtime_intel._handle_client_message(
        {"type": "invalid"},
        "test_client"
    )
    
    # Test invalid intelligence data
    await realtime_intel.process_new_intelligence(
        {"invalid": "data"},
        "test_source"
    )
    
    # Verify error handling didn't crash the service
    assert realtime_intel.intel_manager is not None

@pytest.mark.asyncio
async def test_buffer_management(realtime_intel):
    """Test intelligence buffer management."""
    # Fill buffer beyond capacity
    buffer_size = realtime_intel.intel_manager.buffer_size
    test_data = [
        {
            "type": "test",
            "name": f"Test{i}",
            "timestamp": datetime.now(timezone.utc)
        }
        for i in range(buffer_size + 10)
    ]
    
    for data in test_data:
        await realtime_intel.process_new_intelligence(data, "test_source")
    
    # Verify buffer size is maintained
    assert len(realtime_intel.intel_manager.intelligence_buffer) <= buffer_size
    
    # Verify oldest items were removed
    timestamps = [
        i.get("timestamp") for i in 
        realtime_intel.intel_manager.intelligence_buffer
    ]
    assert sorted(timestamps) == timestamps

@pytest.mark.asyncio
async def test_multiple_clients(realtime_intel):
    """Test handling multiple client connections."""
    # Create multiple mock clients
    clients = [
        (f"client{i}", MockWebSocket())
        for i in range(3)
    ]
    
    # Connect all clients
    for client_id, websocket in clients:
        await realtime_intel.intel_manager.connect(websocket, client_id)
    
    # Broadcast test message
    test_intel = {
        "type": "test",
        "name": "MultiClientTest"
    }
    await realtime_intel.process_new_intelligence(test_intel, "test_source")
    
    # Verify all clients are connected
    assert len(realtime_intel.intel_manager.active_connections) == 3
    
    # Disconnect one client
    await realtime_intel.intel_manager.disconnect(
        clients[0][1],
        clients[0][0]
    )
    assert len(realtime_intel.intel_manager.active_connections) == 2

class MockWebSocket:
    """Mock WebSocket class for testing."""
    async def accept(self):
        pass
        
    async def send_json(self, data: Dict[str, Any]):
        pass
        
    async def receive_json(self) -> Dict[str, Any]:
        return {"type": "test"}
        
    async def close(self, code: int = 1000):
        pass