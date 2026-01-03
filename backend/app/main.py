import os
import logging
import sys
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.gzip import GZipMiddleware
from app.core.config import settings
from app.core.rate_limiter import limiter
from app.core.exceptions import (
    LinkLoadException,
    ScannerException,
    DatabaseException,
    AuthenticationException,
    ValidationException,
    ResourceNotFoundException,
    RateLimitException
)
from app.core.security_middleware import (
    InjectionPreventionMiddleware,
    SecurityHeadersMiddleware,
    security_logger
)
from app.core.logging_config import (
    configure_logging,
    get_system_logger_name,
    get_business_logger_name,
)
from app.api import ws, auth, scan_manager, ws_endpoints, scans, batch_scanner, scanner, risk_analysis, remediation
from app.api import (
    vulnerability_scanner,
    vulnerabilities,
    intelligence,
    domain_verification,
    mitre
)

configure_logging()

logger = logging.getLogger(__name__)
system_logger = logging.getLogger(get_system_logger_name())
business_logger = logging.getLogger(get_business_logger_name())

# Initialize application
app = FastAPI(
    title="Link & Load API",
    description="Comprehensive security scanning platform",
    version="1.0.0",
    docs_url="/docs" if settings.ENABLE_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_DOCS else None,
    # Disable OpenAPI in production for security
    openapi_url="/openapi.json" if settings.ENABLE_DOCS else None
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore

# =============================================================================
# SECURITY MIDDLEWARE STACK (Order matters - first added = last executed)
# =============================================================================

# GZip compression for responses (with security consideration for BREACH attacks)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Trusted Host Middleware - Prevents Host header attacks
if settings.ENVIRONMENT == "production":
    allowed_hosts = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

# Injection Prevention Middleware - A03:2021
app.add_middleware(
    InjectionPreventionMiddleware,
    exempt_paths=["/docs", "/redoc", "/openapi.json", "/health"]
)

# Enhanced Security Headers Middleware - A05:2021
app.add_middleware(
    SecurityHeadersMiddleware,
    enable_hsts=settings.ENVIRONMENT == "production",
    csp_directives={
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-inline'",
        "style-src": "'self' 'unsafe-inline'",
        "img-src": "'self' data: https:",
        "font-src": "'self' data:",
        "connect-src": "'self' wss: https:",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
        "base-uri": "'self'",
        "object-src": "'none'",
        "upgrade-insecure-requests": "" if settings.ENVIRONMENT == "production" else None,
    }
)

# CORS configuration with strict settings
origins = settings.CORS_ORIGINS.split(",") if settings.CORS_ORIGINS else []

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token"],
    expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    # Generate unique request ID for tracing
    import uuid
    request_id = str(uuid.uuid4())
    
    # Log request for security monitoring (A09:2021)
    client_ip = request.client.host if request.client else "unknown"
    system_logger.info(
        f"Request: {request.method} {request.url.path} from {client_ip} [req_id={request_id}]"
    )
    
    response = await call_next(request)
    
    # Add request ID to response for tracing
    response.headers["X-Request-ID"] = request_id
    
    # Core security headers (reinforced by SecurityHeadersMiddleware)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
    
    # Remove server identification headers (use del with check since MutableHeaders doesn't have pop)
    if "Server" in response.headers:
        del response.headers["Server"]
    if "X-Powered-By" in response.headers:
        del response.headers["X-Powered-By"]
    
    return response

# Request size limiting middleware
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Prevent denial of service through large request bodies"""
    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB
    
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_SIZE:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"error": "Request too large", "detail": "Maximum request size is 10MB"}
        )
    
    return await call_next(request)

# Global exception handler
@app.exception_handler(LinkLoadException)
async def linkload_exception_handler(request: Request, exc: LinkLoadException):
    """Handle custom LinkLoad exceptions."""
    # Log security events appropriately
    client_ip = request.client.host if request.client else "unknown"
    
    if isinstance(exc, AuthenticationException):
        security_logger.log_authentication_attempt(
            user_id=None,
            email=None,
            ip_address=client_ip,
            success=False,
            reason=exc.detail
        )
    elif isinstance(exc, RateLimitException):
        security_logger.log_rate_limit_exceeded(
            user_id=getattr(request.state, "user_id", None),
            ip_address=client_ip,
            endpoint=str(request.url.path)
        )
    
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
    """Handle all unhandled exceptions with security considerations."""
    # Log the full error internally but don't expose details to clients
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    # Don't leak internal error details in production
    detail = "An unexpected error occurred. Please try again later."
    if settings.ENVIRONMENT == "development":
        detail = str(exc)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "detail": detail,
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
        # Database tables already created by reset_db.py
        # Skip init_db() to avoid model import issues
        system_logger.info("Skipping database initialization (tables already exist)")
        
        # Initialize Redis cache
        from app.core.cache import cache_manager
        await cache_manager.initialize()
        system_logger.info("Redis cache initialized successfully")
    except Exception as e:
        system_logger.error(f"Failed to initialize services: {e}")
        import traceback
        traceback.print_exc()
        # Don't re-raise - allow app to start anyway

# Cleanup event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    try:
        # Close Redis connections
        from app.core.cache import cache_manager
        await cache_manager.close()
        system_logger.info("Redis cache connections closed")
    except Exception as e:
        system_logger.error(f"Error during cleanup: {e}")

# Register routers
app.include_router(auth.router, prefix=settings.API_PREFIX)  # Authentication routes
app.include_router(ws.router)  # WebSocket router
app.include_router(scanner.router)  # Simple scanner endpoints for E2E tests
app.include_router(vulnerability_scanner.router, prefix=settings.API_PREFIX)
app.include_router(vulnerabilities.router)
app.include_router(intelligence.router, prefix=settings.API_PREFIX)  # Intelligence routes
app.include_router(risk_analysis.router)  # Enhanced risk analysis endpoints
app.include_router(remediation.router, prefix=settings.API_PREFIX)  # Remediation guidance

app.include_router(scan_manager.router, prefix=settings.API_PREFIX)  # Scan management
app.include_router(scans.router)  # Comprehensive scanning endpoints
app.include_router(ws_endpoints.router, prefix=settings.API_PREFIX)  # WebSocket endpoints
app.include_router(batch_scanner.router)  # Batch scanning endpoints
app.include_router(domain_verification.router)  # Domain verification workflows
app.include_router(mitre.router, prefix=settings.API_PREFIX)  # MITRE ATT&CK techniques endpoint

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
        system_logger.error(f"Health check failed: {e}")
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
    system_logger.warning(f"Could not mount reports directory: {e}")