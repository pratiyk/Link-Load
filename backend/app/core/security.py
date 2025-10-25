import uuid
import secrets
import string
from datetime import datetime, timedelta
from typing import Any, Union, Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException, status, Depends, Request, WebSocket
from app.core.config import settings
from app.database.supabase_client import supabase

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class SecurityManager:
    @staticmethod
    def create_access_token(
        subject: Union[str, Any], 
        expires_delta: timedelta = None,
        additional_claims: dict = None
    ) -> str:
        """Create JWT access token with jti for revocation tracking"""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
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
        expire = datetime.utcnow() + timedelta(
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
    def verify_token(token: str) -> Optional[dict]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            # Check if token is revoked
            if supabase.is_token_revoked(payload.get("jti")):
                return None
            return payload
        except JWTError:
            return None

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)

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
    credentials: HTTPAuthorizationCredentials = Depends(security)
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
        
        return user_id
    except JWTError:
        raise credentials_exception

from app.models.user import User
from sqlalchemy.orm import Session
from app.database import get_db

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
        user = db.query(User).filter(User.id == user_id).first()
        return user
    except HTTPException:
        return None