"""End-to-end test suite for Link&Load platform."""
import os
from pathlib import Path

test_env_path = Path(__file__).parent / ".." / ".env.test"
if test_env_path.exists():
    with open(test_env_path, "r", encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            os.environ[key.strip()] = value.strip()

# Ensure in-memory SQLite database for integration tests before app import
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from httpx import AsyncClient
import asyncio
import jwt
import json
from datetime import datetime, timedelta
import websockets
import logging

import app.database as db_module
from app.database import Base, get_db, SessionLocal
from app.core.config import settings
from app.main import app
from app.models.user import User
from app.models.vulnerability_models import VulnerabilityData
from app.services.intelligence_mapping.mitre_mapper import MITREMapper
from app.services.intelligence_mapping.realtime_intel import RealTimeIntelligence

logger = logging.getLogger(__name__)

# Test data
TEST_USER = {
    "email": "test@linkload.io",
    "password": "test_password123!",
    "full_name": "Test User"
}


@pytest.fixture(scope="module", autouse=True)
def configure_test_database():
    """Ensure integration tests use isolated in-memory SQLite."""

    database_url = os.environ["DATABASE_URL"]
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False} if database_url.startswith("sqlite") else {},
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    db_module.engine = engine
    db_module.SessionLocal = TestingSessionLocal
    Base.metadata.bind = engine

    # Import models to register metadata
    import app.models.threat_intel_models  # noqa: F401
    import app.models.vulnerability_models  # noqa: F401
    import app.models.associations  # noqa: F401
    import app.models.user  # noqa: F401

    Base.metadata.create_all(bind=engine)
    try:
        yield
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()

@pytest.fixture(scope="module")
def test_client():
    """Create a test client for API testing."""
    with TestClient(app) as client:
        yield client

@pytest.fixture(scope="module")
def db():
    """Create a test database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture(scope="module")
def auth_headers(test_client):
    """Get authentication headers for test user."""
    # Register test user
    response = test_client.post("/api/v1/auth/register", json=TEST_USER)
    assert response.status_code == 201
    
    # Login and get token
    response = test_client.post("/api/v1/auth/login", data={
        "username": TEST_USER["email"],
        "password": TEST_USER["password"]
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    
    return {"Authorization": f"Bearer {token}"}

@pytest.mark.asyncio
async def test_vulnerability_scanning(test_client, auth_headers):
    """Test the complete vulnerability scanning pipeline."""
    # Test data
    test_url = "https://test-target.com"
    
    # 1. Start scan
    response = test_client.post(
        "/api/v1/scanner/start",
        json={"url": test_url},
        headers=auth_headers
    )
    assert response.status_code == 200
    scan_id = response.json()["scan_id"]
    
    # 2. Poll scan status
    for _ in range(10):  # Poll for max 10 times
        response = test_client.get(
            f"/api/v1/scanner/status/{scan_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        if response.json()["status"] in ["completed", "failed"]:
            break
        await asyncio.sleep(2)
    
    assert response.json()["status"] == "completed"
    
    # 3. Get scan results
    response = test_client.get(
        f"/api/v1/scanner/results/{scan_id}",
        headers=auth_headers
    )
    assert response.status_code == 200
    results = response.json()
    
    # Validate results structure
    assert "vulnerabilities" in results
    assert "risk_score" in results
    assert "mitigations" in results

@pytest.mark.asyncio
async def test_threat_intelligence(test_client, auth_headers, db):
    """Test threat intelligence features."""
    # 1. Create test vulnerability
    vuln = VulnerabilityData(
        title="Test SQL Injection",
        description="A test SQL injection vulnerability",
        severity="HIGH",
        cvss_score=8.5
    )
    db.add(vuln)
    db.commit()
    
    # 2. Test MITRE mapping
    response = test_client.get(
        f"/api/v1/intelligence/mitre-mapping/{vuln.id}",
        headers=auth_headers
    )
    assert response.status_code == 200
    mapping = response.json()
    
    assert "techniques" in mapping
    assert "ttps" in mapping
    assert "confidence_explanation" in mapping
    
    # 3. Test real-time updates
    async with websockets.connect(
        f"ws://localhost:8000/api/v1/intelligence/ws/stream?token={auth_headers['Authorization'].split()[1]}"
    ) as websocket:
        # Send test message
        await websocket.send(json.dumps({
            "type": "subscribe",
            "intel_types": ["malware", "exploit"]
        }))
        
        # Verify connection
        response = await websocket.recv()
        response_data = json.loads(response)
        assert "type" in response_data
        assert response_data["type"] in ["connected", "subscribed"]

@pytest.mark.asyncio
async def test_risk_scoring(test_client, auth_headers, db):
    """Test risk scoring and assessment features."""
    # 1. Create test vulnerability
    vuln = VulnerabilityData(
        title="Critical RCE Vulnerability",
        description="Remote code execution vulnerability in admin panel",
        severity="CRITICAL",
        cvss_score=9.8
    )
    db.add(vuln)
    db.commit()
    
    # 2. Get risk score
    response = test_client.get(
        f"/api/v1/intelligence/risk-score/{vuln.id}",
        headers=auth_headers
    )
    assert response.status_code == 200
    score_data = response.json()
    
    # Validate score components
    assert "base_score" in score_data
    assert "temporal_score" in score_data
    assert "environmental_score" in score_data
    assert 0 <= score_data["base_score"] <= 10
    
    # 3. Test risk score explanation
    assert "factors" in score_data
    assert isinstance(score_data["factors"], dict)
    assert "ml_confidence" in score_data
    assert 0 <= score_data["ml_confidence"] <= 1

@pytest.mark.asyncio
async def test_remediation_suggestions(test_client, auth_headers):
    """Test remediation suggestion features."""
    # Test data
    test_vulnerability = {
        "title": "Outdated Dependencies",
        "description": "Multiple outdated npm packages with known vulnerabilities",
        "severity": "HIGH",
        "affected_components": ["package.json", "yarn.lock"]
    }
    
    # 1. Get remediation suggestions
    response = test_client.post(
        "/api/v1/remediation/suggest",
        json=test_vulnerability,
        headers=auth_headers
    )
    assert response.status_code == 200
    suggestions = response.json()
    
    # Validate suggestions
    assert "steps" in suggestions
    assert "commands" in suggestions
    assert "priority" in suggestions
    assert isinstance(suggestions["steps"], list)
    assert len(suggestions["steps"]) > 0

def test_error_handling(test_client, auth_headers):
    """Test error handling and edge cases."""
    # 1. Test invalid scan target
    response = test_client.post(
        "/api/v1/scanner/start",
        json={"url": "not-a-valid-url"},
        headers=auth_headers
    )
    assert response.status_code == 422
    
    # 2. Test non-existent vulnerability
    response = test_client.get(
        "/api/v1/intelligence/risk-score/99999",
        headers=auth_headers
    )
    assert response.status_code == 404
    
    # 3. Test invalid authentication
    response = test_client.get(
        "/api/v1/scanner/results/123",
        headers={"Authorization": "Bearer invalid-token"}
    )
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_performance(test_client, auth_headers):
    """Test performance and concurrency handling."""
    # 1. Test concurrent scan requests
    async with AsyncClient(app=app, base_url="http://test") as ac:
        tasks = []
        for i in range(5):
            tasks.append(
                ac.post(
                    "/api/v1/scanner/start",
                    json={"url": f"https://test{i}.com"},
                    headers=auth_headers
                )
            )
        
        responses = await asyncio.gather(*tasks)
        assert all(r.status_code == 200 for r in responses)
    
    # 2. Test WebSocket connection limits
    websocket_tasks = []
    for _ in range(3):
        websocket_tasks.append(
            websockets.connect(
                f"ws://localhost:8000/api/v1/intelligence/ws/stream?token={auth_headers['Authorization'].split()[1]}"
            )
        )
    
    connections = await asyncio.gather(*websocket_tasks)
    for ws in connections:
        await ws.close()

if __name__ == "__main__":
    pytest.main(["-v", "--asyncio-mode=auto"])