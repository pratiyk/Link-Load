from fastapi import APIRouter
from app.core.health import health_checker
from app.core.rate_limiter import rate_limiter

router = APIRouter()

@router.get("/health")
async def health_check():
    """Get system health status"""
    return await health_checker.check_health()

@router.get("/health/rate-limits")
async def rate_limit_status():
    """Get current rate limit status"""
    return {
        "active_connections": {
            ip: len(connections) 
            for ip, connections in rate_limiter.connections.items()
        },
        "request_counts": rate_limiter.request_counts
    }