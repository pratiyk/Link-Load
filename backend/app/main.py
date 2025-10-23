import os
import logging
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.core.config import settings
from app.core.rate_limiter import limiter
from app.core.exceptions import (
    LinkLoadException,
    ScannerException,
    DatabaseException,
    AuthenticationException,
    ValidationException,
    ResourceNotFoundException
)
from app.api import ws, auth, scan_manager, ws_endpoints, scans
from app.api import (
    vulnerability_scanner,
    vulnerabilities,
    intelligence
)

logger = logging.getLogger(__name__)

# Initialize application
app = FastAPI(
    title="Link & Load API",
    description="Comprehensive security scanning platform",
    version="1.0.0",
    docs_url="/docs" if settings.ENABLE_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_DOCS else None
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore

# CORS configuration
origins = settings.CORS_ORIGINS.split(",") if settings.CORS_ORIGINS else []

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    return response

# Global exception handler
@app.exception_handler(LinkLoadException)
async def linkload_exception_handler(request: Request, exc: LinkLoadException):
    """Handle custom LinkLoad exceptions."""
    logger.error(f"LinkLoad exception: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_code,
            "detail": exc.detail,
            "status_code": exc.status_code
        }
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "detail": "An unexpected error occurred. Please try again later.",
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    )

# Force HTTPS in production
if settings.ENVIRONMENT == "production":
    app.add_middleware(HTTPSRedirectMiddleware)

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    try:
        # Initialize database
        from app.database import init_db
        init_db()
        logger.info("Database tables initialized successfully")
        
        # Initialize Redis cache
        from app.core.cache import cache_manager
        await cache_manager.initialize()
        logger.info("Redis cache initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")

# Cleanup event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    try:
        # Close Redis connections
        from app.core.cache import cache_manager
        await cache_manager.close()
        logger.info("Redis cache connections closed")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

# Register routers
app.include_router(auth.router, prefix=settings.API_PREFIX)  # Authentication routes
app.include_router(ws.router)  # WebSocket router
app.include_router(vulnerability_scanner.router, prefix=settings.API_PREFIX)
app.include_router(vulnerabilities.router)
app.include_router(intelligence.router, prefix=settings.API_PREFIX)  # Intelligence routes
app.include_router(scan_manager.router, prefix=settings.API_PREFIX)  # Scan management
app.include_router(scans.router)  # Comprehensive scanning endpoints
app.include_router(ws_endpoints.router, prefix=settings.API_PREFIX)  # WebSocket endpoints

# Health check endpoints
@app.get("/")
async def root():
    return {"message": "Link & Load API is running"}

@app.get("/health")
async def health():
    """Health check endpoint with database connectivity test."""
    try:
        from app.database import engine
        from sqlalchemy import text
        # Test database connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_health = True
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        db_health = False
    
    return {
        "status": "healthy" if db_health else "degraded",
        "database": db_health,
        "version": "1.0.0"
    }

# Serve static files for reports (create directory if it doesn't exist)
reports_dir = "/tmp/reports" if os.name != "nt" else os.path.join(os.getcwd(), "reports")
os.makedirs(reports_dir, exist_ok=True)

try:
    app.mount("/reports", StaticFiles(directory=reports_dir), name="reports")
except Exception as e:
    logger.warning(f"Could not mount reports directory: {e}")