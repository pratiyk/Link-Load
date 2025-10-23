import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
from datetime import datetime
from uuid import uuid4
from types import SimpleNamespace

from app.main import app
from app.core.security import get_current_user
from app.models.scan_models import BatchScanStatus

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def mock_batch_processor():
    return Mock()


@pytest.fixture(autouse=True)
def override_auth():
    user = SimpleNamespace(id=str(uuid4()), email="test@example.com")

    async def _fake_current_user():
        return user

    app.dependency_overrides[get_current_user] = _fake_current_user
    try:
        yield user
    finally:
        app.dependency_overrides.pop(get_current_user, None)

def test_start_batch_scan(client, mock_batch_processor):
    with patch('app.api.batch_scanner.batch_processor', mock_batch_processor):
        
        response = client.post("/api/v1/batch/scan", json={
            "targets": ["https://example1.com", "https://example2.com"],
            "scan_config": {
                "scan_types": ["comprehensive"],
                "include_low_risk": False,
                "max_scan_time": 3600
            },
            "concurrent_scans": 2,
            "force_new_scan": False
        })
        
        assert response.status_code == 202
        assert "batch_id" in response.json()
        assert mock_batch_processor.start_batch_scan.called

def test_get_batch_status(client, mock_batch_processor):
    with patch('app.api.batch_scanner.batch_processor', mock_batch_processor):
        
        batch_id = str(uuid4())
        mock_batch_processor.get_batch_status.return_value = {
            "batch_id": batch_id,
            "status": BatchScanStatus.RUNNING,
            "total_targets": 2,
            "completed_targets": 1,
            "started_at": datetime.utcnow().isoformat()
        }
        
        response = client.get(f"/api/v1/batch/scan/{batch_id}")
        
        assert response.status_code == 200
        assert response.json()["batch_id"] == batch_id
        mock_batch_processor.get_batch_status.assert_called_once()

def test_cancel_batch_scan(client, mock_batch_processor):
    with patch('app.api.batch_scanner.batch_processor', mock_batch_processor):
        
        batch_id = str(uuid4())
        mock_batch_processor.update_batch_status.return_value = True
        
        response = client.delete(f"/api/v1/batch/scan/{batch_id}")
        
        assert response.status_code == 204
        mock_batch_processor.update_batch_status.assert_called_once_with(
            batch_id,
            BatchScanStatus.CANCELLED
        )

def test_batch_scan_not_found(client, mock_batch_processor):
    with patch('app.api.batch_scanner.batch_processor', mock_batch_processor):
        
        batch_id = str(uuid4())
        mock_batch_processor.get_batch_status.return_value = None
        
        response = client.get(f"/api/v1/batch/scan/{batch_id}")
        
        assert response.status_code == 404
        assert response.json()["detail"] == "Batch scan not found"

def test_batch_scan_validation(client):
    # Test with empty targets
    response = client.post("/api/v1/batch/scan", json={
        "targets": [],
        "scan_config": {
            "scan_types": ["comprehensive"],
            "include_low_risk": False
        }
    })
    assert response.status_code == 422

    # Test with invalid scan type
    response = client.post("/api/v1/batch/scan", json={
        "targets": ["https://example.com"],
        "scan_config": {
            "scan_types": ["invalid_type"],
            "include_low_risk": False
        }
    })
    assert response.status_code == 422

    # Test with invalid URL
    response = client.post("/api/v1/batch/scan", json={
        "targets": ["not_a_url"],
        "scan_config": {
            "scan_types": ["comprehensive"],
            "include_low_risk": False
        }
    })
    assert response.status_code == 422