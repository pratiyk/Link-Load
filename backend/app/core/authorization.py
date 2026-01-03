"""
Authorization and data access control utilities.

Ensures that all user-specific data (scans, domains, etc.) is properly
scoped to the authenticated user and cannot be accessed by other users.
"""
import logging
from typing import Optional, Dict, Any, Union

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.domain_verification import DomainVerification

logger = logging.getLogger(__name__)


class AccessDeniedException(HTTPException):
    """Raised when user attempts to access data they don't own"""
    def __init__(self, detail: str = "Access denied"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )


def verify_scan_ownership(scan_data: Optional[Dict[str, Any]], user_id: str) -> Dict[str, Any]:
    """
    Verify that the given scan belongs to the specified user.
    
    Args:
        scan_data: The scan record from Supabase
        user_id: The user ID to check ownership against
        
    Returns:
        The validated scan data
        
    Raises:
        AccessDeniedException: If scan doesn't belong to user
    """
    if not scan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    scan_owner = scan_data.get("user_id")
    if not scan_owner:
        logger.warning(
            f"Scan {scan_data.get('scan_id')} has no user_id - treating as inaccessible"
        )
        raise AccessDeniedException("Scan data is malformed")
    
    if scan_owner != user_id:
        logger.warning(
            f"Unauthorized access attempt: User {user_id} tried to access "
            f"scan {scan_data.get('scan_id')} owned by {scan_owner}"
        )
        raise AccessDeniedException("You do not have access to this scan")
    
    return scan_data


def verify_domain_ownership(
    db: Session,
    domain_id: str,
    user_id: str
) -> DomainVerification:
    """
    Verify that the given domain belongs to the specified user.
    
    Args:
        db: Database session
        domain_id: The domain ID to check
        user_id: The user ID to check ownership against
        
    Returns:
        The domain record if ownership is verified
        
    Raises:
        AccessDeniedException: If domain doesn't belong to user
    """
    domain = db.query(DomainVerification).filter(
        DomainVerification.id == domain_id,
        DomainVerification.user_id == user_id
    ).first()
    
    if not domain:
        logger.warning(
            f"Unauthorized access attempt: User {user_id} tried to access "
            f"domain {domain_id}"
        )
        raise AccessDeniedException("You do not have access to this domain")
    
    return domain


def _extract_user_id(current_user: Union[User, Dict[str, Any], None]) -> Optional[str]:
    """Return the user ID regardless of whether the user is an ORM object or Supabase dict."""
    if not current_user:
        return None
    if isinstance(current_user, dict):
        user_id = current_user.get("id") or current_user.get("user_id")
    else:
        user_id = getattr(current_user, "id", None)
    return str(user_id) if user_id else None


def require_authenticated_user(current_user: Optional[Union[User, Dict[str, Any]]]) -> Union[User, Dict[str, Any]]:
    """
    Ensure that the current request has an authenticated user.
    
    Args:
        current_user: The user from dependency injection
        
    Returns:
        The authenticated user
        
    Raises:
        HTTPException: If user is not authenticated
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    user_id = _extract_user_id(current_user)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user object"
        )
    
    return current_user


def get_user_id(current_user: Union[User, Dict[str, Any]]) -> str:
    """
    Extract and validate user ID from authenticated user.
    
    Args:
        current_user: The authenticated user
        
    Returns:
        The user's ID
        
    Raises:
        HTTPException: If user ID is invalid
    """
    user_id = _extract_user_id(current_user)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User ID not found in token"
        )
    return str(user_id)
