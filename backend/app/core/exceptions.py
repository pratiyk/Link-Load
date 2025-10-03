"""Custom exception classes for the LinkLoad application."""
from fastapi import HTTPException, status
from typing import Any, Dict, Optional


class LinkLoadException(HTTPException):
    """Base exception for all LinkLoad errors with HTTP status support."""
    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: str,
        headers: Optional[Dict[str, Any]] = None
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.error_code = error_code


class ScannerException(LinkLoadException):
    """Exception raised when scanner operations fail."""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="SCANNER_ERROR"
        )


class DatabaseException(LinkLoadException):
    """Exception raised when database operations fail."""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="DATABASE_ERROR"
        )


class AuthenticationException(LinkLoadException):
    """Exception raised when authentication fails."""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code="AUTHENTICATION_ERROR",
            headers={"WWW-Authenticate": "Bearer"}
        )


class ValidationException(LinkLoadException):
    """Exception raised when input validation fails."""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail,
            error_code="VALIDATION_ERROR"
        )


class ConfigurationException(LinkLoadException):
    """Exception raised when configuration is invalid or missing."""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="CONFIGURATION_ERROR"
        )


class ResourceNotFoundException(LinkLoadException):
    """Exception raised when a requested resource is not found."""
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
            error_code="NOT_FOUND"
        )


class RateLimitException(LinkLoadException):
    """Exception raised when rate limits are exceeded."""
    def __init__(self, detail: str = "Too many requests. Please try again later."):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            error_code="RATE_LIMIT_EXCEEDED"
        )


class ExternalServiceException(LinkLoadException):
    """Exception raised when external service calls fail."""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail,
            error_code="EXTERNAL_SERVICE_ERROR"
        )


class AuthorizationException(LinkLoadException):
    """Exception raised when authorization fails."""
    def __init__(self, detail: str = "You don't have permission to access this resource"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            error_code="AUTHORIZATION_ERROR"
        )
