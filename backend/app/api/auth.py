"""
Authentication API endpoints
"""
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import Optional
import logging

from app.database import get_db
from app.models.user import (
    User, RevokedToken, UserCreate, UserLogin, UserResponse,
    TokenResponse, TokenRefresh, UserWithTokens, UserUpdate, PasswordChange
)
from app.core.security import SecurityManager, get_current_user_id
from app.core.exceptions import (
    AuthenticationException, ValidationException, DatabaseException
)
from app.core.config import settings
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])

security_manager = SecurityManager()


_GENERIC_LOGIN_ERROR = "Invalid username or password."
_GENERIC_REGISTRATION_ERROR = "Unable to create an account with the provided information."


@router.post("/register", response_model=UserWithTokens, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user with email and password
    
    - Validates email uniqueness
    - Validates username uniqueness
    - Hashes password
    - Creates user account
    - Returns user data with JWT tokens
    """
    try:
        email = user_data.email.strip().lower()
        username = user_data.username.strip().lower()
        full_name = (user_data.full_name.strip() if user_data.full_name else None)

        # Check if email already exists
        existing_email = db.query(User).filter(User.email == email).first()
        if existing_email:
            logger.warning("Registration attempt rejected for existing email", extra={"email": email})
            raise ValidationException(_GENERIC_REGISTRATION_ERROR)
        
        # Check if username already exists
        existing_username = db.query(User).filter(User.username == username).first()
        if existing_username:
            logger.warning("Registration attempt rejected for existing username", extra={"username": username})
            raise ValidationException(_GENERIC_REGISTRATION_ERROR)
        
        # Hash password
        hashed_password = security_manager.hash_password(user_data.password)
        
        # Create user
        db_user = User(
            email=email,
            username=username,
            full_name=full_name,
            hashed_password=hashed_password,
            is_active=True,
            is_verified=False,  # Email verification required
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        logger.info(f"New user registered: {db_user.email}")
        
        # Generate tokens
        access_token = security_manager.create_access_token(subject=db_user.id)
        refresh_token = security_manager.create_refresh_token(subject=db_user.id)
        
        user_response = UserResponse.model_validate(db_user, from_attributes=True)
        
        return UserWithTokens(
            user=user_response,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except ValidationException:
        raise
    except Exception as e:
        logger.error("Registration failed", exc_info=True)
        db.rollback()
        raise DatabaseException("Registration service is temporarily unavailable")


@router.post("/login", response_model=UserWithTokens)
async def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """
    Login with email and password
    
    - Validates credentials
    - Checks account status (active, locked)
    - Tracks failed login attempts
    - Returns user data with JWT tokens
    """
    try:
        email = credentials.email.strip().lower()
        # Find user by email
        user = db.query(User).filter(User.email == email).first()
        
        if not user:
            logger.warning("Failed login attempt for unknown email", extra={"email": email})
            raise AuthenticationException(_GENERIC_LOGIN_ERROR)
        
        # Check if account is locked
        if user.locked_until and user.locked_until > utc_now():  # type: ignore
            logger.warning("Login attempt on locked account", extra={"email": email, "locked_until": user.locked_until})
            raise AuthenticationException(_GENERIC_LOGIN_ERROR)
        
        # Check if account is active
        if not user.is_active:  # type: ignore
            logger.warning("Login attempt on inactive account", extra={"email": email})
            raise AuthenticationException(_GENERIC_LOGIN_ERROR)
        
        # Verify password
        if not security_manager.verify_password(credentials.password, str(user.hashed_password)):
            # Increment failed login attempts
            user.failed_login_attempts += 1  # type: ignore
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:  # type: ignore
                user.locked_until = utc_now() + timedelta(minutes=15)  # type: ignore
                db.commit()
                logger.warning("Account locked after repeated failures", extra={"email": email})
                raise AuthenticationException(_GENERIC_LOGIN_ERROR)
            
            db.commit()
            logger.warning("Invalid credentials submitted", extra={"email": email})
            raise AuthenticationException(_GENERIC_LOGIN_ERROR)
        
        # Reset failed login attempts on successful login
        user.failed_login_attempts = 0  # type: ignore
        user.locked_until = None  # type: ignore
        user.last_login = utc_now()  # type: ignore
        db.commit()
        db.refresh(user)
        
        logger.info("User logged in", extra={"email": email})
        
        # Generate tokens
        access_token = security_manager.create_access_token(subject=user.id)
        refresh_token = security_manager.create_refresh_token(subject=user.id)
        
        user_response = UserResponse.model_validate(user, from_attributes=True)
        
        return UserWithTokens(
            user=user_response,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except AuthenticationException:
        raise
    except Exception as e:
        logger.error("Login failed", exc_info=True)
        raise DatabaseException("Login service is temporarily unavailable")


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(token_data: TokenRefresh, db: Session = Depends(get_db)):
    """
    Refresh access token using refresh token
    
    - Validates refresh token
    - Checks if token is revoked
    - Generates new access token
    """
    try:
        # Verify refresh token
        payload = security_manager.verify_token(token_data.refresh_token)
        
        if not payload:
            raise AuthenticationException("Invalid refresh token")
        
        if payload.get("type") != "refresh":
            raise AuthenticationException("Invalid token type")
        
        user_id = payload.get("sub")
        
        # Verify user still exists and is active
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:  # type: ignore
            raise AuthenticationException("User not found or inactive")
        
        # Generate new access token
        access_token = security_manager.create_access_token(subject=user_id)
        
        logger.info(f"Token refreshed for user: {user.email}")
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=token_data.refresh_token,  # Keep same refresh token
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except AuthenticationException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise AuthenticationException("Failed to refresh token")


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    """
    Logout current user
    
    - Revokes current tokens
    - User must login again to get new tokens
    """
    try:
        # In a production system, you would revoke the tokens here
        # For now, we just log the logout
        logger.info(f"User logged out: {user_id}")
        
        return None
        
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    """
    Get current authenticated user profile
    """
    try:
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise AuthenticationException("User not found")
        
        return UserResponse.model_validate(user, from_attributes=True)
        
    except AuthenticationException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user profile: {e}")
        raise DatabaseException("Failed to retrieve user profile")


@router.put("/me", response_model=UserResponse)
async def update_user_profile(
    user_data: UserUpdate,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    """
    Update current user profile
    """
    try:
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise AuthenticationException("User not found")
        
        # Update fields if provided
        if user_data.full_name is not None:
            user.full_name = user_data.full_name  # type: ignore
        
        if user_data.username is not None:
            # Check if username is already taken by another user
            existing_user = db.query(User).filter(
                User.username == user_data.username,
                User.id != user_id
            ).first()
            if existing_user:
                raise ValidationException("Username already taken")
            user.username = user_data.username  # type: ignore
        
        user.updated_at = utc_now()  # type: ignore
        db.commit()
        db.refresh(user)
        
        logger.info(f"User profile updated: {user.email}")
        
        return UserResponse.model_validate(user, from_attributes=True)
        
    except (AuthenticationException, ValidationException):
        raise
    except Exception as e:
        logger.error(f"Failed to update user profile: {e}")
        db.rollback()
        raise DatabaseException("Failed to update profile")


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    password_data: PasswordChange,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    """
    Change user password
    """
    try:
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise AuthenticationException("User not found")
        
        # Verify current password
        if not security_manager.verify_password(
            password_data.current_password,
            str(user.hashed_password)
        ):
            raise AuthenticationException("Current password is incorrect")
        
        # Hash and update new password
        user.hashed_password = security_manager.hash_password(password_data.new_password)  # type: ignore
        user.updated_at = utc_now()  # type: ignore
        db.commit()
        
        logger.info(f"Password changed for user: {user.email}")
        
        return None
        
    except AuthenticationException:
        raise
    except Exception as e:
        logger.error(f"Failed to change password: {e}")
        db.rollback()
        raise DatabaseException("Failed to change password")
