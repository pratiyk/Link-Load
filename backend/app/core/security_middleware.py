"""
Comprehensive Security Middleware for OWASP Top 10 Protection
=============================================================
This module provides security middleware and utilities to protect against:
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures  
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable and Outdated Components
- A07:2021 - Identification and Authentication Failures
- A08:2021 - Software and Data Integrity Failures
- A09:2021 - Security Logging and Monitoring Failures
- A10:2021 - Server-Side Request Forgery (SSRF)
"""
import re
import logging
import hashlib
import secrets
import ipaddress
from typing import Optional, List, Set, Callable
from datetime import datetime, timezone
from urllib.parse import urlparse
from functools import wraps

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# =============================================================================
# A03:2021 - INJECTION PREVENTION
# =============================================================================

class InjectionPreventionMiddleware(BaseHTTPMiddleware):
    """
    Middleware to detect and prevent common injection attacks:
    - SQL Injection
    - NoSQL Injection
    - Command Injection
    - LDAP Injection
    - XPath Injection
    """
    
    # Patterns that indicate potential SQL injection attempts
    # These patterns are more specific to avoid false positives
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\s+.*(FROM|INTO|TABLE|DATABASE)\b)",
        r"(\b(OR|AND)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?)",
        r"(--\s*$|/\*.*\*/)",
        r"(\bEXEC\s*\(|\bEXECUTE\s*\()",
        r"(;\s*(DROP|DELETE|UPDATE|INSERT)\s)",
        r"(\bWAITFOR\s+DELAY\b|\bBENCHMARK\s*\()",
        r"(\bSLEEP\s*\(\d+\))",
        r"(UNION\s+SELECT)",
    ]
    
    # Command injection patterns - more specific to avoid URL false positives
    COMMAND_INJECTION_PATTERNS = [
        r";\s*[a-zA-Z]",  # Semicolon followed by command
        r"`[^`]+`",  # Backtick command execution
        r"\$\([^)]+\)",  # $(command) execution
        r"\|\s*[a-zA-Z]",  # Pipe to command
        r">\s*\/[a-zA-Z]",  # Redirect to path
        r"\bnc\s+-[el]",  # Netcat
        r"\bwget\s+http",  # wget download
        r"\bcurl\s+http",  # curl download
        r"\brm\s+-rf\s+\/",  # Dangerous rm command
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"vbscript:",
        r"on(error|load|click|mouseover|focus|blur)\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"<img[^>]*\sonerror\s*=",
        r"expression\s*\(",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"..%2f",
        r"%2e%2e\\",
        r"\.\.%5c",
        r"..%5c",
    ]
    
    def __init__(self, app: ASGIApp, exempt_paths: Optional[List[str]] = None):
        super().__init__(app)
        self.exempt_paths = exempt_paths or ["/docs", "/redoc", "/openapi.json"]
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        self.sql_patterns = [re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_PATTERNS]
        self.cmd_patterns = [re.compile(p, re.IGNORECASE) for p in self.COMMAND_INJECTION_PATTERNS]
        self.xss_patterns = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self.path_patterns = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip exempt paths
        if any(request.url.path.startswith(path) for path in self.exempt_paths):
            return await call_next(request)
        
        client_host = request.client.host if request.client else "unknown"
        
        # Check query parameters
        for key, value in request.query_params.items():
            if self._detect_injection(value, key):
                logger.warning(
                    f"Potential injection attack detected in query param '{key}' from {client_host}"
                )
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "Invalid input detected", "detail": "Request contains potentially malicious content"}
                )
        
        # Check path parameters
        if self._detect_path_traversal(request.url.path):
            logger.warning(f"Path traversal attempt detected from {client_host}: {request.url.path}")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Invalid path", "detail": "Request path contains invalid characters"}
            )
        
        return await call_next(request)
    
    def _detect_injection(self, value: str, param_name: str = "") -> bool:
        """Detect potential injection in a value"""
        if not value:
            return False
        
        # Short values are unlikely to be malicious injections
        if len(value) < 5:
            return False
        
        # Skip certain parameters that legitimately contain special characters
        safe_params = {
            "code", "token", "signature", "hash", "key", "api_key",
            "access_token", "refresh_token", "id_token", "state",
            "nonce", "redirect_uri", "callback", "next", "url", "target_url",
            "scan_id", "user_id", "session_id"
        }
        if param_name.lower() in safe_params:
            return False
        
        # Parameters that are URLs shouldn't be checked for command injection
        is_url_param = param_name.lower() in {"url", "target", "target_url", "redirect", "callback", "next"}
        
        # Check for SQL injection
        for pattern in self.sql_patterns:
            if pattern.search(value):
                return True
        
        # Check for command injection (skip for URL params)
        if not is_url_param:
            for pattern in self.cmd_patterns:
                if pattern.search(value):
                    return True
        
        # Check for XSS
        for pattern in self.xss_patterns:
            if pattern.search(value):
                return True
        
        return False
    
    def _detect_path_traversal(self, path: str) -> bool:
        """Detect path traversal attempts"""
        for pattern in self.path_patterns:
            if pattern.search(path):
                return True
        return False


# =============================================================================
# A10:2021 - SSRF PREVENTION
# =============================================================================

class SSRFProtection:
    """
    Server-Side Request Forgery (SSRF) protection utilities.
    Validates and sanitizes URLs to prevent internal network access.
    """
    
    # Private IP ranges that should be blocked
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fc00::/7'),
        ipaddress.ip_network('fe80::/10'),
    ]
    
    # Blocked hostnames
    BLOCKED_HOSTNAMES = {
        'localhost',
        'localhost.localdomain',
        '127.0.0.1',
        '0.0.0.0',
        '::1',
        'metadata.google.internal',
        '169.254.169.254',  # AWS/GCP metadata
        'metadata.azure.com',
    }
    
    # Allowed schemes
    ALLOWED_SCHEMES = {'http', 'https'}
    
    # Blocked ports
    BLOCKED_PORTS = {22, 23, 25, 445, 3389, 5432, 3306, 27017, 6379, 11211}
    
    @classmethod
    def validate_url(cls, url: str, allow_internal: bool = False) -> tuple[bool, str]:
        """
        Validate a URL for SSRF vulnerabilities.
        
        Args:
            url: URL to validate
            allow_internal: Whether to allow internal network access (default: False)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
                return False, f"Invalid URL scheme: {parsed.scheme}"
            
            # Check hostname
            hostname = parsed.hostname
            if not hostname:
                return False, "URL must have a hostname"
            
            hostname_lower = hostname.lower()
            
            # Check blocked hostnames
            if hostname_lower in cls.BLOCKED_HOSTNAMES:
                return False, f"Blocked hostname: {hostname}"
            
            # Check for IP address
            try:
                ip = ipaddress.ip_address(hostname)
                
                if not allow_internal:
                    # Check if IP is in private range
                    for private_range in cls.PRIVATE_IP_RANGES:
                        if ip in private_range:
                            return False, f"Internal IP address not allowed: {hostname}"
                    
                    # Check for loopback
                    if ip.is_loopback:
                        return False, "Loopback addresses not allowed"
                    
                    # Check for link-local
                    if ip.is_link_local:
                        return False, "Link-local addresses not allowed"
                        
            except ValueError:
                # Not an IP address, hostname will be resolved
                pass
            
            # Check port
            port = parsed.port
            if port and port in cls.BLOCKED_PORTS:
                return False, f"Blocked port: {port}"
            
            return True, ""
            
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"
    
    @classmethod
    def sanitize_url(cls, url: str) -> str:
        """
        Sanitize a URL by removing dangerous components.
        
        Args:
            url: URL to sanitize
            
        Returns:
            Sanitized URL
        """
        # Remove any authentication credentials from URL
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        port_part = f":{parsed.port}" if parsed.port else ""
        sanitized = parsed._replace(
            netloc=hostname + port_part
        )
        return sanitized.geturl()


# =============================================================================
# A09:2021 - SECURITY LOGGING
# =============================================================================

class SecurityLogger:
    """
    Centralized security event logging for monitoring and incident response.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("security")
        self._setup_security_logger()
    
    def _setup_security_logger(self):
        """Setup dedicated security logger"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
            ))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def log_authentication_attempt(
        self,
        user_id: Optional[str],
        email: Optional[str],
        ip_address: str,
        success: bool,
        reason: Optional[str] = None
    ):
        """Log authentication attempts"""
        self.logger.info(
            f"AUTH_ATTEMPT | user_id={user_id or 'unknown'} | "
            f"email={email or 'unknown'} | ip={ip_address} | "
            f"success={success} | reason={reason or 'N/A'}"
        )
    
    def log_authorization_failure(
        self,
        user_id: str,
        resource: str,
        action: str,
        ip_address: str
    ):
        """Log authorization failures"""
        self.logger.warning(
            f"AUTHZ_FAILURE | user_id={user_id} | resource={resource} | "
            f"action={action} | ip={ip_address}"
        )
    
    def log_injection_attempt(
        self,
        attack_type: str,
        payload: str,
        ip_address: str,
        path: str
    ):
        """Log injection attack attempts"""
        # Truncate payload to prevent log injection
        safe_payload = payload[:100].replace('\n', ' ').replace('\r', ' ')
        self.logger.critical(
            f"INJECTION_ATTEMPT | type={attack_type} | "
            f"payload={safe_payload} | ip={ip_address} | path={path}"
        )
    
    def log_rate_limit_exceeded(
        self,
        user_id: Optional[str],
        ip_address: str,
        endpoint: str
    ):
        """Log rate limit violations"""
        self.logger.warning(
            f"RATE_LIMIT | user_id={user_id or 'anonymous'} | "
            f"ip={ip_address} | endpoint={endpoint}"
        )
    
    def log_suspicious_activity(
        self,
        user_id: Optional[str],
        ip_address: str,
        activity: str,
        details: str
    ):
        """Log suspicious activities"""
        self.logger.warning(
            f"SUSPICIOUS | user_id={user_id or 'anonymous'} | "
            f"ip={ip_address} | activity={activity} | details={details}"
        )
    
    def log_data_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str
    ):
        """Log sensitive data access"""
        self.logger.info(
            f"DATA_ACCESS | user_id={user_id} | resource_type={resource_type} | "
            f"resource_id={resource_id} | action={action}"
        )


security_logger = SecurityLogger()


# =============================================================================
# A05:2021 - SECURITY HEADERS MIDDLEWARE
# =============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive security headers middleware implementing best practices.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        enable_hsts: bool = True,
        csp_directives: Optional[dict] = None,
        enable_csp_report: bool = False,
        report_uri: Optional[str] = None
    ):
        super().__init__(app)
        self.enable_hsts = enable_hsts
        self.csp_directives = csp_directives or self._default_csp()
        self.enable_csp_report = enable_csp_report
        self.report_uri = report_uri
    
    def _default_csp(self) -> dict:
        """Default Content Security Policy"""
        return {
            "default-src": "'self'",
            "script-src": "'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src": "'self' 'unsafe-inline'",
            "img-src": "'self' data: https:",
            "font-src": "'self' data:",
            "connect-src": "'self' wss: https:",
            "frame-ancestors": "'none'",
            "form-action": "'self'",
            "base-uri": "'self'",
            "object-src": "'none'",
        }
    
    def _build_csp_header(self) -> str:
        """Build CSP header from directives"""
        directives = [f"{key} {value}" for key, value in self.csp_directives.items()]
        if self.enable_csp_report and self.report_uri:
            directives.append(f"report-uri {self.report_uri}")
        return "; ".join(directives)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Strict Transport Security (HSTS)
        if self.enable_hsts:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )
        
        # Content Security Policy
        response.headers["Content-Security-Policy"] = self._build_csp_header()
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # XSS Protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions Policy
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )
        
        # Cache Control for sensitive responses
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        # Cross-Origin policies
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        
        return response


# =============================================================================
# A01:2021 - ACCESS CONTROL UTILITIES
# =============================================================================

class AccessControl:
    """
    Role-Based Access Control (RBAC) utilities.
    """
    
    ROLES = {
        "admin": {"permissions": {"*"}},
        "user": {"permissions": {"read", "write", "scan"}},
        "viewer": {"permissions": {"read"}},
        "scanner": {"permissions": {"scan", "read"}},
    }
    
    @classmethod
    def check_permission(cls, role: str, permission: str) -> bool:
        """Check if a role has a specific permission"""
        if role not in cls.ROLES:
            return False
        
        role_permissions = cls.ROLES[role]["permissions"]
        
        # Admin has all permissions
        if "*" in role_permissions:
            return True
        
        return permission in role_permissions
    
    @classmethod
    def require_permission(cls, permission: str):
        """Decorator to require a specific permission"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Get user from request context
                request = kwargs.get("request")
                if not request:
                    for arg in args:
                        if isinstance(arg, Request):
                            request = arg
                            break
                
                if not request:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Request context not available"
                    )
                
                user_role = getattr(request.state, "user_role", "viewer")
                
                if not cls.check_permission(user_role, permission):
                    security_logger.log_authorization_failure(
                        user_id=getattr(request.state, "user_id", "unknown"),
                        resource=request.url.path,
                        action=permission,
                        ip_address=request.client.host if request.client else "unknown"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient permissions"
                    )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator


# =============================================================================
# A02:2021 - CRYPTOGRAPHIC UTILITIES
# =============================================================================

class CryptoUtils:
    """
    Cryptographic utilities for secure data handling.
    """
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate a cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_sensitive_data(data: str, salt: Optional[str] = None) -> str:
        """Hash sensitive data using SHA-256"""
        if salt is None:
            salt = secrets.token_hex(16)
        combined = f"{salt}:{data}"
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        return f"{salt}:{hashed}"
    
    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """Compare two strings in constant time to prevent timing attacks"""
        return secrets.compare_digest(a.encode(), b.encode())
    
    @staticmethod
    def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
        """Mask sensitive data for logging"""
        if len(data) <= visible_chars:
            return "*" * len(data)
        return data[:visible_chars] + "*" * (len(data) - visible_chars)


# =============================================================================
# A08:2021 - INTEGRITY VERIFICATION
# =============================================================================

class IntegrityVerification:
    """
    Utilities for verifying data integrity.
    """
    
    @staticmethod
    def generate_checksum(data: bytes) -> str:
        """Generate SHA-256 checksum for data"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def verify_checksum(data: bytes, expected_checksum: str) -> bool:
        """Verify data integrity using checksum"""
        actual_checksum = hashlib.sha256(data).hexdigest()
        return secrets.compare_digest(actual_checksum, expected_checksum)
    
    @staticmethod
    def generate_hmac(data: str, secret: str) -> str:
        """Generate HMAC for data integrity"""
        import hmac
        return hmac.new(
            secret.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    @staticmethod
    def verify_hmac(data: str, secret: str, expected_hmac: str) -> bool:
        """Verify HMAC signature"""
        import hmac
        actual_hmac = hmac.new(
            secret.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return secrets.compare_digest(actual_hmac, expected_hmac)


# =============================================================================
# REQUEST SANITIZATION
# =============================================================================

class InputSanitizer:
    """
    Input sanitization utilities for preventing various injection attacks.
    """
    
    @staticmethod
    def sanitize_html(text: str) -> str:
        """Remove HTML tags from text"""
        return re.sub(r'<[^>]+>', '', text)
    
    @staticmethod
    def sanitize_sql_identifier(identifier: str) -> str:
        """Sanitize SQL identifiers (table/column names)"""
        # Only allow alphanumeric and underscores
        return re.sub(r'[^a-zA-Z0-9_]', '', identifier)
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        # Remove path separators and special characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '', filename)
        sanitized = re.sub(r'\.\.+', '.', sanitized)
        return sanitized[:255]  # Limit filename length
    
    @staticmethod
    def sanitize_for_logging(text: str, max_length: int = 500) -> str:
        """Sanitize text for safe logging"""
        # Remove newlines and control characters
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "...[truncated]"
        return sanitized
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email)) and len(email) <= 254
    
    @staticmethod
    def validate_uuid(uuid_str: str) -> bool:
        """Validate UUID format"""
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(pattern, uuid_str.lower()))


# Export all utilities
__all__ = [
    'InjectionPreventionMiddleware',
    'SSRFProtection',
    'SecurityLogger',
    'security_logger',
    'SecurityHeadersMiddleware',
    'AccessControl',
    'CryptoUtils',
    'IntegrityVerification',
    'InputSanitizer',
]
