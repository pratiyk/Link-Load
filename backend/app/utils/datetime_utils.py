"""Helpers for timezone-aware UTC timestamps."""
from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the current UTC time with timezone information."""
    return datetime.now(timezone.utc)


def utc_now_naive() -> datetime:
    """Return the current UTC time as a naive datetime for legacy storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
