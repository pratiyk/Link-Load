"""Batch scan orchestration utilities."""
from __future__ import annotations

import asyncio
import logging
import inspect
from datetime import datetime
from typing import Any, Dict, Iterable, Optional, cast
from uuid import uuid4

from fastapi import BackgroundTasks
from pydantic import ValidationError

from app.database.supabase_client import supabase
from app.models.scan_models import BatchScanStatus, ScanRequest
from app.services.scanner_orchestrator import OWASPOrchestrator

logger = logging.getLogger(__name__)

# Shared orchestrator instance reused across batch jobs to avoid repeated setup costs.
scanner_orchestrator = OWASPOrchestrator()


class BatchProcessor:
    """Coordinate multiple scan executions as a single batch workload."""

    def __init__(self, concurrency: int = 3):
        self._concurrency = max(1, concurrency)
        self._semaphore = asyncio.Semaphore(self._concurrency)

    def set_concurrency(self, concurrency: int) -> None:
        """Adjust parallelism for subsequent batch processing."""

        self._concurrency = max(1, concurrency)
        self._semaphore = asyncio.Semaphore(self._concurrency)

    async def start_batch_scan(
        self,
        batch_id: str,
        targets: Iterable[Any],
        scan_config: Any,
        user_id: str,
        background_tasks: BackgroundTasks,
        concurrency: Optional[int] = None,
    ) -> None:
        """Persist batch metadata and schedule asynchronous processing."""
        normalized_targets = [str(target) for target in targets]
        if concurrency:
            self.set_concurrency(concurrency)

        config_payload = self._normalize_scan_config(scan_config)
        now = datetime.utcnow()

        supabase.insert_batch_scan(
            {
                "batch_id": batch_id,
                "user_id": user_id,
                "status": BatchScanStatus.PENDING,
                "total_targets": len(normalized_targets),
                "completed_targets": 0,
                "failed_targets": 0,
                "scan_config": config_payload,
                "started_at": now,
            }
        )

        background_tasks.add_task(
            self.process_batch,
            batch_id,
            normalized_targets,
            config_payload,
            user_id,
        )

    async def process_batch(
        self,
        batch_id: str,
        targets: Iterable[str],
        scan_config: Dict[str, Any],
        user_id: str,
    ) -> None:
        """Execute each scan sequentially while updating Supabase state."""
        supabase.update_batch_scan(
            batch_id,
            {
                "status": BatchScanStatus.RUNNING,
                "started_at": datetime.utcnow(),
            },
        )

        completed = 0
        failed = 0
        base_config = self._normalize_scan_config(scan_config)

        for index, target in enumerate(targets, start=1):
            scan_id = f"{batch_id}-{index}-{uuid4().hex[:8]}"
            try:
                request_payload = {**base_config, "target_url": target}
                request = self._ensure_scan_request(request_payload)
            except ValidationError as exc:
                failed += 1
                logger.error(
                    "Batch %s validation failed for %s: %s",
                    batch_id,
                    target,
                    exc,
                    exc_info=True,
                )
                supabase.update_batch_scan(
                    batch_id,
                    {
                        "status": BatchScanStatus.FAILED,
                        "completed_targets": completed,
                        "failed_targets": failed,
                    },
                )
                continue
            try:
                async with self._semaphore:
                    result = scanner_orchestrator.run_scan(scan_id, request, user_id)
                    if inspect.isawaitable(result):
                        await result
                completed += 1
            except Exception as exc:  # pragma: no cover - log for diagnostics
                failed += 1
                logger.error("Batch %s scan failed for %s: %s", batch_id, target, exc, exc_info=True)
                supabase.update_batch_scan(
                    batch_id,
                    {
                        "status": BatchScanStatus.FAILED,
                        "completed_targets": completed,
                        "failed_targets": failed,
                    },
                )
            else:
                supabase.update_batch_scan(
                    batch_id,
                    {
                        "status": BatchScanStatus.RUNNING,
                        "completed_targets": completed,
                        "failed_targets": failed,
                    },
                )

        final_status = BatchScanStatus.COMPLETED if failed == 0 else BatchScanStatus.FAILED
        supabase.update_batch_scan(
            batch_id,
            {
                "status": final_status,
                "completed_targets": completed,
                "failed_targets": failed,
                "completed_at": datetime.utcnow(),
            },
        )

    async def get_batch_status(self, batch_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetch batch metadata together with aggregated scan IDs."""
        batch = supabase.fetch_batch_scan(batch_id)
        if not batch or batch.get("user_id") != user_id:
            return None

        batch["scan_results"] = supabase.fetch_batch_scan_results(batch_id)
        return batch

    async def update_batch_status(self, batch_id: str, status: BatchScanStatus) -> bool:
        """Force-update batch status (e.g. from admin tooling)."""
        result = supabase.update_batch_scan(
            batch_id,
            {
                "status": status,
                "updated_at": datetime.utcnow(),
            },
        )
        return result is not None

    @staticmethod
    def _ensure_scan_request(config: Any) -> ScanRequest:
        if isinstance(config, ScanRequest):
            return config
        if hasattr(config, "model_dump"):
            config = config.model_dump(mode="json", exclude_none=True)
        if isinstance(config, dict):
            validator = getattr(ScanRequest, "model_validate", None)
            if callable(validator):
                return cast(ScanRequest, validator(config))
            return ScanRequest(**config)
        raise TypeError("scan_config must be a ScanRequest or dict")

    @staticmethod
    def _model_dump(request: ScanRequest) -> Dict[str, Any]:
        dump_method = getattr(request, "model_dump", None)
        if callable(dump_method):
            return cast(Dict[str, Any], dump_method(mode="json", exclude_none=True))
        return cast(Dict[str, Any], request.dict())

    @staticmethod
    def _normalize_scan_config(config: Any) -> Dict[str, Any]:
        if isinstance(config, ScanRequest):
            payload = BatchProcessor._model_dump(config)
        elif hasattr(config, "model_dump"):
            payload = cast(Dict[str, Any], config.model_dump(mode="json", exclude_none=True))
        elif isinstance(config, dict):
            payload = dict(config)
        else:
            raise TypeError("scan_config must be serializable to a dict")

        payload.pop("target_url", None)
        return payload


# Shared processor instance for API usage
batch_processor = BatchProcessor()