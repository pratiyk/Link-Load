import inspect
import logging
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status

from app.core.security import get_current_user
from app.models.scan_models import BatchScanRequest, BatchScanStatus
from app.services.batch_processor import batch_processor

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/batch", tags=["Batch Scanning"])


async def _maybe_await(result: Any) -> Any:
    """Await values when needed without assuming coroutine usage."""

    if inspect.isawaitable(result):
        return await result
    return result


def _extract_user_id(user: Any) -> str:
    """Support both ORM user objects and lightweight test doubles."""

    if hasattr(user, "id") and getattr(user, "id"):
        return str(getattr(user, "id"))
    if isinstance(user, dict) and user.get("id"):
        return str(user["id"])
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid user context")


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED)
async def start_batch_scan(
    request: BatchScanRequest,
    background_tasks: BackgroundTasks,
    current_user: Any = Depends(get_current_user),
):
    """Start a batch scan for multiple targets."""

    batch_id = str(uuid4())
    user_id = _extract_user_id(current_user)

    try:
        await _maybe_await(
            batch_processor.start_batch_scan(
                batch_id=batch_id,
                targets=request.targets,
                scan_config=request.scan_config,
                user_id=user_id,
                background_tasks=background_tasks,
                concurrency=request.concurrent_scans,
            )
        )
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error("Failed to start batch scan %s: %s", batch_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start batch scan",
        ) from exc

    return {
        "batch_id": batch_id,
        "message": "Batch scan started successfully",
        "total_targets": len(request.targets),
    }


@router.get("/scan/{batch_id}")
async def get_batch_scan_status(
    batch_id: str,
    current_user: Any = Depends(get_current_user),
):
    """Get the status and results of a batch scan."""

    user_id = _extract_user_id(current_user)

    try:
        batch_status = await _maybe_await(batch_processor.get_batch_status(batch_id, user_id))
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error("Failed to retrieve batch %s: %s", batch_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve batch scan status",
        ) from exc

    if not batch_status:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch scan not found")

    return batch_status


@router.delete("/scan/{batch_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_batch_scan(
    batch_id: str,
    current_user: Any = Depends(get_current_user),
):
    """Cancel a running batch scan."""

    _extract_user_id(current_user)
    try:
        success = await _maybe_await(batch_processor.update_batch_status(batch_id, BatchScanStatus.CANCELLED))
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error("Failed to cancel batch %s: %s", batch_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel batch scan",
        ) from exc

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch scan not found")

    return Response(status_code=status.HTTP_204_NO_CONTENT)