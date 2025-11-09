import os
import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timezone
from uuid import uuid4
from pathlib import Path

from app.models.scan_models import (
    BatchScanRequest, 
    BatchScanConfig,
    BatchScanStatus, 
    ScanType, 
)
from pydantic import HttpUrl, TypeAdapter
from app.services.batch_processor import BatchProcessor

# Set test environment file before importing any app modules
os.environ["ENV_FILE"] = str(Path(__file__).parent / ".env.test")

@pytest.fixture
def batch_processor():
    return BatchProcessor()

@pytest.fixture
def mock_scanner_orchestrator():
    return Mock()

@pytest.fixture
def mock_supabase():
    return Mock()

@pytest.fixture
def sample_batch_request():
    http_url = TypeAdapter(HttpUrl)
    target1 = http_url.validate_python("https://example1.com")
    target2 = http_url.validate_python("https://example2.com")
    target3 = http_url.validate_python("https://example.com")
    return BatchScanRequest(
        targets=[target1, target2],
        scan_config=BatchScanConfig(
            target_url=target3,
            scan_types=[ScanType.COMPREHENSIVE],
            include_low_risk=False,
            max_scan_time=3600,
            notify_on_completion=False,
            authenticated=False,
            auth_username=None,
            auth_password=None,
            auth_type="form",
            login_url=None,
            custom_headers=None,
            user_agent=None,
            proxy_url=None,
            follow_redirects=True,
            scan_depth=2,
            nuclei_templates=None,
            nuclei_tags=None,
            nuclei_severity=None,
            notification_email=None,
            notification_webhook=None,
        ),
        concurrent_scans=2,
        notify_on_completion=False,
        force_new_scan=False,
    )

@pytest.mark.asyncio
async def test_start_batch_scan(batch_processor, mock_supabase, sample_batch_request):
    with patch('app.services.batch_processor.supabase', mock_supabase):
        batch_id = str(uuid4())
        user_id = str(uuid4())
        background_tasks = Mock()

        # Test starting batch scan
        await batch_processor.start_batch_scan(
            batch_id=batch_id,
            targets=sample_batch_request.targets,
            scan_config=sample_batch_request.scan_config,
            user_id=user_id,
            background_tasks=background_tasks
        )

        # Verify database insert was called
        mock_supabase.insert_batch_scan.assert_called_once()
        insert_args = mock_supabase.insert_batch_scan.call_args[0][0]
        assert insert_args["batch_id"] == batch_id
        assert insert_args["user_id"] == user_id
        assert insert_args["status"] == BatchScanStatus.PENDING
        assert insert_args["total_targets"] == len(sample_batch_request.targets)

        # Verify background task was added
        background_tasks.add_task.assert_called_once()

@pytest.mark.asyncio
async def test_process_batch(batch_processor, mock_scanner_orchestrator, mock_supabase):
    with patch('app.services.batch_processor.supabase', mock_supabase), \
         patch('app.services.batch_processor.scanner_orchestrator', mock_scanner_orchestrator):
        
        batch_id = str(uuid4())
        user_id = str(uuid4())
        targets = ["https://example1.com", "https://example2.com"]
        scan_config = {
            "scan_types": ["comprehensive"],
            "include_low_risk": False,
            "max_scan_time": 3600
        }

        # Process batch
        await batch_processor.process_batch(batch_id, targets, scan_config, user_id)

        # Verify scanner was called for each target
        assert mock_scanner_orchestrator.run_scan.call_count == len(targets)

        # Verify status updates
        mock_supabase.update_batch_scan.assert_called()
        assert any(
            call[0][1]["status"] == BatchScanStatus.COMPLETED 
            for call in mock_supabase.update_batch_scan.call_args_list
        )

@pytest.mark.asyncio
async def test_get_batch_status(batch_processor, mock_supabase):
    with patch('app.services.batch_processor.supabase', mock_supabase):
        batch_id = str(uuid4())
        user_id = str(uuid4())

        # Mock batch data
        mock_batch = {
            "batch_id": batch_id,
            "user_id": user_id,
            "status": BatchScanStatus.COMPLETED,
            "total_targets": 2,
            "completed_targets": 2,
            "failed_targets": 0,
            "scan_config": {},
            "started_at": datetime.now(timezone.utc).isoformat()
        }
        mock_supabase.fetch_batch_scan.return_value = mock_batch
        mock_supabase.fetch_batch_scan_results.return_value = [
            f"{batch_id}-example1",
            f"{batch_id}-example2"
        ]

        # Get batch status
        status = await batch_processor.get_batch_status(batch_id, user_id)

        # Verify response
        assert status is not None
        assert status["batch_id"] == batch_id
        assert status["user_id"] == user_id
        assert status["status"] == BatchScanStatus.COMPLETED
        
        # Verify database calls
        mock_supabase.fetch_batch_scan.assert_called_once_with(batch_id)
        mock_supabase.fetch_batch_scan_results.assert_called_once_with(batch_id)

@pytest.mark.asyncio
async def test_update_batch_status(batch_processor, mock_supabase):
    with patch('app.services.batch_processor.supabase', mock_supabase):
        batch_id = str(uuid4())
        
        # Test status update
        await batch_processor.update_batch_status(batch_id, BatchScanStatus.RUNNING)
        
        # Verify database update
        mock_supabase.update_batch_scan.assert_called_once()
        update_args = mock_supabase.update_batch_scan.call_args[0]
        assert update_args[0] == batch_id
        assert update_args[1]["status"] == BatchScanStatus.RUNNING

@pytest.mark.asyncio
async def test_batch_scan_error_handling(batch_processor, mock_supabase, mock_scanner_orchestrator):
    with patch('app.services.batch_processor.supabase', mock_supabase), \
         patch('app.services.batch_processor.scanner_orchestrator', mock_scanner_orchestrator):
        
        batch_id = str(uuid4())
        user_id = str(uuid4())
        
        # Simulate scanner error
        mock_scanner_orchestrator.run_scan.side_effect = Exception("Scanner error")
        
        # Process batch with error
        await batch_processor.process_batch(
            batch_id,
            ["https://example.com"],
            {"scan_types": ["comprehensive"]},
            user_id
        )
        
        # Verify error handling
        assert any(
            call[0][1]["status"] == BatchScanStatus.FAILED
            for call in mock_supabase.update_batch_scan.call_args_list
        )