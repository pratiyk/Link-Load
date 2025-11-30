"""Utility script to delete legacy scans that were stored with the
placeholder user_id "anonymous".

Run from repo root:
    python backend/scripts/cleanup_anonymous_scans.py

Requires access to Supabase credentials via environment variables
(SUPABASE_URL, SUPABASE_KEY, SUPABASE_SERVICE_KEY, etc.).
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, List, Sequence

# Ensure project root is on sys.path so "app" package can be imported
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.database.supabase_client import supabase

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def chunk_list(items: Sequence[str], chunk_size: int = 50) -> List[List[str]]:
    """Yield successive chunks from a list."""
    return [list(items[i : i + chunk_size]) for i in range(0, len(items), chunk_size)]


def delete_anonymous_scans() -> None:
    """Remove scans and related vulnerabilities tied to user_id='anonymous'."""
    logger.info("Querying for anonymous scans...")
    response = supabase.admin.table("owasp_scans").select("scan_id").eq("user_id", "anonymous").execute()
    rows: List[dict[str, Any]] = [row for row in (response.data or []) if isinstance(row, dict)]

    if not rows:
        logger.info("No anonymous scans found; nothing to delete.")
        return

    scan_ids: List[str] = [str(row["scan_id"]) for row in rows if row.get("scan_id")]
    logger.info("Found %d anonymous scan(s)", len(scan_ids))

    deleted_vulns = 0
    for chunk in chunk_list(scan_ids):
        logger.info("Deleting vulnerabilities for %d scan(s)...", len(chunk))
        supabase.admin.table("owasp_vulnerabilities").delete().in_("scan_id", chunk).execute()
        deleted_vulns += len(chunk)

    logger.info("Deleting scan records themselves...")
    supabase.admin.table("owasp_scans").delete().eq("user_id", "anonymous").execute()

    logger.info(
        "Cleanup complete. Removed %d scan(s) and associated vulnerability batches.",
        len(scan_ids),
    )


if __name__ == "__main__":
    delete_anonymous_scans()
