import logging
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import JSONResponse
from uuid import uuid4

from app.core.security import get_current_user, User
from app.models.scan_models import BatchScanRequest, BatchScan, BatchScanStatus
from app.services.batch_processor import batch_processor

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/batch", tags=["Batch Scanning"])

@router.post("/scan", response_model=BatchScan)
async def start_batch_scan(
    request: BatchScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """Start a batch scan for multiple targets"""
    try:
        batch_id = str(uuid4())
        
        # Configure scan with user settings
        scan_config = {
            **request.scan_config.dict(),
            "force_new_scan": request.force_new_scan
        }
        
        # Start batch processing
        await batch_processor.start_batch_scan(
            batch_id=batch_id,
            targets=[str(t) for t in request.targets],
            scan_config=scan_config,
            user_id=current_user.id,
            background_tasks=background_tasks
        )
        
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "batch_id": batch_id,
                "message": "Batch scan started successfully",
                "total_targets": len(request.targets)
            }
        )
    except Exception as e:
        logger.error(f"Failed to start batch scan: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start batch scan"
        )

@router.get("/scan/{batch_id}", response_model=BatchScan)
async def get_batch_scan_status(
    batch_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get the status and results of a batch scan"""
    try:
        batch_status = await batch_processor.get_batch_status(batch_id, current_user.id)
        if not batch_status:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Batch scan not found"
            )
        
        return batch_status
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get batch scan status: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve batch scan status"
        )

@router.delete("/scan/{batch_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_batch_scan(
    batch_id: str,
    current_user: User = Depends(get_current_user)
):
    """Cancel a running batch scan"""
    try:
        # Update batch status to cancelled
        cancelled = await batch_processor.update_batch_status(
            batch_id, 
            BatchScanStatus.CANCELLED
        )
        
        if not cancelled:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Batch scan not found"
            )
        
        return JSONResponse(
            status_code=status.HTTP_204_NO_CONTENT,
            content=None
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel batch scan: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel batch scan"
        )