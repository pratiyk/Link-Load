"""
Rate limiting configuration for LinkLoad API
"""
from slowapi import Limiter
from slowapi.util import get_remote_address
from limits.errors import ConfigurationError
from fastapi import Request
from typing import Optional
import os

try:  # Redis is optional when running in-memory limits
    import redis  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - redis optional in tests
    redis = None

# Initialize rate limiter
# For development, we'll use in-memory storage
# For production, use Redis for distributed rate limiting
def _should_force_memory_storage() -> bool:
    """Determine if rate limiting should use in-memory storage."""
    if os.getenv("RATE_LIMIT_ENABLED", "true").lower() in {"0", "false", "no"}:
        return True
    if os.getenv("PYTEST_CURRENT_TEST"):
        return True
    return False


def _resolve_storage_uri() -> str:
    """Return the storage URI, falling back to memory if Redis is unavailable."""
    if _should_force_memory_storage():
        return "memory://"

    storage_uri = os.getenv("RATE_LIMIT_STORAGE_URI") or os.getenv("REDIS_URL")
    if not storage_uri:
        return "memory://"

    if storage_uri.startswith("redis") and redis is not None:
        try:
            redis.from_url(storage_uri, socket_connect_timeout=1).ping()
            return storage_uri
        except Exception:
            # Redis configured but unreachable – fall back to memory for reliability
            return "memory://"

    return storage_uri


def _create_limiter() -> Limiter:
    storage_uri = _resolve_storage_uri()
    try:
        return Limiter(
            key_func=get_remote_address,
            storage_uri=storage_uri,
            default_limits=["60/minute", "1000/hour"]
        )
    except ConfigurationError:
        return Limiter(
            key_func=get_remote_address,
            storage_uri="memory://",
            default_limits=["60/minute", "1000/hour"]
        )


limiter = _create_limiter()


async def get_user_id_from_token(request: Request) -> str:
    """
    Extract user ID from JWT token for per-user rate limiting
    Falls back to IP address if no token is present
    """
    try:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            from app.core.security import SecurityManager
            security_manager = SecurityManager()
            payload = security_manager.verify_token(token)
            if payload:
                return f"user:{payload.get('sub')}"
    except Exception:
        pass
    return get_remote_address(request)


# Rate limit configurations for different endpoint types
RATE_LIMITS = {
    "auth_register": "5/hour",           # 5 registrations per hour
    "auth_login": "10/minute",           # 10 login attempts per minute
    "auth_refresh": "30/minute",         # 30 token refreshes per minute
    "scan_start": "10/minute",           # 10 scans per minute
    "scan_status": "60/minute",          # 60 status checks per minute
    "vulnerability_scan": "20/minute",   # 20 vulnerability scans per minute
    "link_scan": "30/minute",            # 30 link scans per minute
    "threat_scan": "30/minute",          # 30 threat scans per minute
    "darkweb_scan": "10/minute",         # 10 dark web scans per minute
    "phishing_scan": "30/minute",        # 30 phishing scans per minute
    "attack_surface": "5/minute",        # 5 attack surface scans per minute
    "general": "60/minute",              # 60 general requests per minute
}


def get_rate_limit(endpoint_type: str = "general") -> str:
    """Get rate limit string for endpoint type"""
    return RATE_LIMITS.get(endpoint_type, RATE_LIMITS["general"])
