import uuid
import secrets
import string
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Union, Optional

import bcrypt
import httpx
from jose import jwt, JWTError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException, status, Depends, Request, WebSocket
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.database.supabase_client import supabase
# Use auto_error=False so we can return 401 instead of default 403 for missing credentials
security = HTTPBearer(auto_error=False)
logger = logging.getLogger(__name__)

class SecurityManager:
    @staticmethod
    def create_access_token(
        subject: Union[str, Any], 
        expires_delta: timedelta = None,
        additional_claims: dict = None
    ) -> str:
        """Create JWT access token with jti for revocation tracking"""
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        jti = str(uuid.uuid4())
        to_encode = {
            "exp": expire, 
            "sub": str(subject),
            "jti": jti,
            "type": "access"
        }
        if additional_claims:
            to_encode.update(additional_claims)
        
        encoded_jwt = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
        )
        return encoded_jwt

    @staticmethod
    def create_refresh_token(subject: Union[str, Any]) -> str:
        """Create JWT refresh token with jti for revocation"""
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
        jti = str(uuid.uuid4())
        to_encode = {
            "exp": expire, 
            "sub": str(subject), 
            "type": "refresh",
            "jti": jti
        }
        encoded_jwt = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
        )
        return encoded_jwt

    @staticmethod
    def verify_supabase_token(token: str) -> Optional[dict]:
        """Validate Supabase JWT using the project REST API."""
        if not settings.SUPABASE_URL or not settings.SUPABASE_KEY:
            logger.debug("Supabase configuration missing; skipping token verification")
            return None

        headers = {
            "Authorization": f"Bearer {token}",
            "apikey": settings.SUPABASE_KEY,
        }
        user_endpoint = f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/user"

        try:
            with httpx.Client(timeout=5) as client:
                response = client.get(user_endpoint, headers=headers)
        except httpx.HTTPError as exc:
            logger.warning("Supabase token introspection failed: %s", exc)
            return None

        if response.status_code != status.HTTP_200_OK:
            logger.debug(
                "Supabase user endpoint returned %s during token verification",
                response.status_code,
            )
            return None

        try:
            user_data = response.json()
        except ValueError:
            logger.warning("Supabase user endpoint returned invalid JSON")
            return None

        try:
            claims = jwt.get_unverified_claims(token)
        except JWTError:
            claims = {}

        payload = {
            "sub": user_data.get("id") or claims.get("sub"),
            "email": user_data.get("email") or claims.get("email"),
            "provider": "supabase",
            "app_metadata": user_data.get("app_metadata") or claims.get("app_metadata") or {},
            "user_metadata": user_data.get("user_metadata") or claims.get("user_metadata") or {},
            "email_confirmed_at": user_data.get("email_confirmed_at") or claims.get("email_confirmed_at"),
            "jti": claims.get("jti"),
            "exp": claims.get("exp"),
        }

        if not payload.get("sub"):
            logger.debug("Supabase token payload missing subject")
            return None

        return payload

    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            # Check if token is revoked
            if supabase.is_token_revoked(payload.get("jti")):
                return None
            payload["provider"] = "native"
            return payload
        except JWTError:
            pass

        supabase_payload = SecurityManager.verify_supabase_token(token)
        if supabase_payload:
            return supabase_payload

        return None

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt."""
        if not isinstance(password, str):
            raise TypeError("Password must be a string")
        password_bytes = password.encode("utf-8")
        hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash."""
        if not plain_password or not hashed_password:
            return False
        try:
            password_bytes = plain_password.encode("utf-8")
            hashed_bytes = hashed_password.encode("utf-8")
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        except ValueError:
            return False

    @staticmethod
    def generate_api_key(length: int = 32) -> str:
        """Generate secure API key"""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def generate_secure_token(length: int = 64) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)

    @staticmethod
    def revoke_token(jti: str, expires: datetime):
        """Add token to revocation list"""
        supabase.revoke_token(jti, expires)

security_manager = SecurityManager()


async def verify_token(token: str) -> Optional[str]:
    """Async-compatible wrapper returning the token subject.

    Returns None when the token is invalid or revoked so callers can
    close connections or raise auth errors without crashing.
    """
    payload = security_manager.verify_token(token)
    if not payload:
        return None
    return payload.get("sub")

async def get_current_user_id(
    request: Request, 
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> str:
    """Validate JWT token and return user ID
    
    Args:
        request: FastAPI request object
        credentials: JWT credentials from auth header
        
    Returns:
        str: User ID from token
        
    Raises:
        HTTPException: If token is invalid, expired or revoked
    """
    """Extract user ID from JWT token with revocation check"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        if not credentials:
            raise credentials_exception
            
        payload = security_manager.verify_token(credentials.credentials)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked or is invalid",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        
        # Add token to request state for potential revocation
        request.state.jti = payload.get("jti")
        request.state.token_exp = payload.get("exp")
        request.state.auth_payload = payload
        request.state.auth_provider = payload.get("provider", "native")
        
        return user_id
    except JWTError:
        raise credentials_exception

from app.models.user import User
from sqlalchemy.orm import Session
from app.database import get_db

_USERNAME_SANITIZE_PATTERN = re.compile(r"[^a-zA-Z0-9_-]")
_MAX_USERNAME_LENGTH = 50
_BASE_USERNAME_LENGTH = 40


def _sanitize_username(raw: Optional[str]) -> str:
    if not raw:
        return "user"
    sanitized = _USERNAME_SANITIZE_PATTERN.sub("_", raw.strip().lower())
    sanitized = sanitized or "user"
    return sanitized[:_MAX_USERNAME_LENGTH]


def _ensure_unique_username(db: Session, base_username: str, user_id: Optional[str] = None) -> str:
    base = base_username[:_BASE_USERNAME_LENGTH] or "user"
    candidate = base
    suffix = 1

    while True:
        existing = db.query(User).filter(User.username == candidate).first()
        if not existing or (user_id and existing.id == user_id):
            return candidate

        candidate = f"{base}_{suffix}"[:_MAX_USERNAME_LENGTH]
        suffix += 1


def _ensure_supabase_user(db: Session, payload: dict) -> User:
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Supabase token payload missing subject",
        )

    email = (payload.get("email") or "").lower()
    if not email:
        email = f"{user_id}@supabase.local"

    metadata = payload.get("user_metadata") or {}
    preferred_username = (
        metadata.get("username")
        or metadata.get("preferred_username")
        or (email.split("@")[0] if email else f"user_{user_id[:8]}")
    )
    sanitized_username = _sanitize_username(preferred_username)
    username = _ensure_unique_username(db, sanitized_username, user_id=user_id)
    full_name = metadata.get("full_name") or metadata.get("name")
    is_verified = bool(payload.get("email_confirmed_at"))

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        user = db.query(User).filter(User.email == email).first()
        if user and user.id != user_id:
            user.id = user_id

    created_new_user = False
    if not user:
        user = User(
            id=user_id,
            email=email,
            username=username,
            hashed_password=security_manager.hash_password(secrets.token_urlsafe(32)),
            full_name=full_name,
            is_active=True,
            is_verified=is_verified,
        )
        db.add(user)
        created_new_user = True

    changed = created_new_user

    if user.email != email:
        user.email = email
        changed = True

    if (created_new_user or not getattr(user, "username", None)) and user.username != username:
        user.username = username
        changed = True

    if full_name is not None and user.full_name != full_name:
        user.full_name = full_name
        changed = True

    if not user.is_active:
        user.is_active = True
        changed = True

    if user.is_verified != is_verified:
        user.is_verified = is_verified
        changed = True

    if not user.hashed_password:
        user.hashed_password = security_manager.hash_password(secrets.token_urlsafe(16))
        changed = True

    if changed:
        try:
            db.flush()
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            logger.error("Failed to synchronize Supabase user %s: %s", user_id, exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to synchronize Supabase user",
            ) from exc

        if created_new_user:
            logger.info("Created local user entry for Supabase subject %s", user_id)

        db.refresh(user)

    return user

async def get_current_user(
    request: Request, 
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token
    
    Args:
        request: FastAPI request object
        credentials: JWT credentials from auth header
        db: Database session
        
    Returns:
        User: User object for authenticated user
        
    Raises:
        HTTPException: If token is invalid, expired or revoked
    """
    user_id = await get_current_user_id(request, credentials)
    auth_payload = getattr(request.state, "auth_payload", {})

    if auth_payload.get("provider") == "supabase":
        user = _ensure_supabase_user(db, auth_payload)
    else:
        user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

async def get_current_user_ws(websocket: WebSocket) -> Optional[str]:
    """Authenticate user for WebSocket connection
    
    Args:
        websocket: WebSocket connection instance
        
    Returns:
        Optional[str]: User ID if authentication successful, None otherwise
        
    Note:
        Closes WebSocket connection with appropriate status code on authentication failure
    """
    try:
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return None
        
        payload = security_manager.verify_token(token)
        if not payload:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return None
            
        return payload.get("sub")
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Get current authenticated user from JWT token (optional)
    
    Returns None if no authentication is provided instead of raising an error.
    Useful for endpoints that work with or without authentication.
    """
    if not credentials:
        return None
    
    try:
        user_id = await get_current_user_id(request, credentials)
        auth_payload = getattr(request.state, "auth_payload", {})
        if auth_payload.get("provider") == "supabase":
            try:
                return _ensure_supabase_user(db, auth_payload)
            except HTTPException as exc:
                logger.debug(
                    "Supabase user sync skipped in optional auth: %s",
                    getattr(exc, "detail", str(exc)),
                )
                return None

        return db.query(User).filter(User.id == user_id).first()
    except HTTPException:
        return None