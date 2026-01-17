"""
Authentication API endpoints
"""
import logging
import secrets
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.database import get_db
from app.database.supabase_client import supabase
from app.models.user import (
    User, RevokedToken, UserCreate, UserLogin, UserResponse,
    TokenResponse, TokenRefresh, UserWithTokens, UserUpdate, PasswordChange,
    ForgotPasswordRequest, ResetPasswordRequest
)
from app.core.security import SecurityManager, get_current_user_id
from app.core.exceptions import (
    AuthenticationException, ValidationException, DatabaseException
)
from app.core.config import settings
from app.core.rate_limiter import limiter, RATE_LIMITS
from app.core.security_middleware import security_logger
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])

security_manager = SecurityManager()


_GENERIC_LOGIN_ERROR = "Invalid username or password."
_GENERIC_REGISTRATION_ERROR = "Unable to create an account with the provided information."


class SupabaseEmailConfirmRequest(BaseModel):
    email: EmailStr


@router.post("/register", response_model=UserWithTokens, status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMITS["auth_register"])
async def register_user(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user with email and password
    
    - Validates email uniqueness
    - Validates username uniqueness
    - Hashes password
    - Creates user account
    - Returns user data with JWT tokens
    """
    client_ip = request.client.host if request.client else "unknown"
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
@limiter.limit(RATE_LIMITS["auth_login"])
async def login(request: Request, credentials: UserLogin, db: Session = Depends(get_db)):
    """
    Login with email and password
    
    - Validates credentials
    - Checks account status (active, locked)
    - Tracks failed login attempts
    - Returns user data with JWT tokens
    """
    client_ip = request.client.host if request.client else "unknown"
    try:
        email = credentials.email.strip().lower()
        # Find user by email
        user = db.query(User).filter(User.email == email).first()
        
        if not user:
            security_logger.log_authentication_attempt(
                user_id=None,
                email=email,
                ip_address=client_ip,
                success=False,
                reason="User not found"
            )
            raise AuthenticationException(_GENERIC_LOGIN_ERROR)
        
        # Check if account is locked
        if user.locked_until and user.locked_until > utc_now():  # type: ignore
            security_logger.log_authentication_attempt(
                user_id=str(user.id),
                email=email,
                ip_address=client_ip,
                success=False,
                reason="Account locked"
            )
            raise AuthenticationException(_GENERIC_LOGIN_ERROR)
        
        # Check if account is active
        if not user.is_active:  # type: ignore
            security_logger.log_authentication_attempt(
                user_id=str(user.id),
                email=email,
                ip_address=client_ip,
                success=False,
                reason="Account inactive"
            )
            raise AuthenticationException(_GENERIC_LOGIN_ERROR)
        
        # Verify password
        if not security_manager.verify_password(credentials.password, str(user.hashed_password)):
            # Increment failed login attempts
            user.failed_login_attempts += 1  # type: ignore
            
            security_logger.log_authentication_attempt(
                user_id=str(user.id),
                email=email,
                ip_address=client_ip,
                success=False,
                reason=f"Invalid password (attempt {user.failed_login_attempts})"
            )
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:  # type: ignore
                user.locked_until = utc_now() + timedelta(minutes=15)  # type: ignore
                db.commit()
                logger.warning("Account locked after repeated failures", extra={"email": email})
                raise AuthenticationException(_GENERIC_LOGIN_ERROR)
            
            db.commit()
            raise AuthenticationException(_GENERIC_LOGIN_ERROR)
        
        # Reset failed login attempts on successful login
        user.failed_login_attempts = 0  # type: ignore
        user.locked_until = None  # type: ignore
        user.last_login = utc_now()  # type: ignore
        db.commit()
        db.refresh(user)
        
        # Log successful authentication
        security_logger.log_authentication_attempt(
            user_id=str(user.id),
            email=email,
            ip_address=client_ip,
            success=True,
            reason=None
        )
        
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
@limiter.limit(RATE_LIMITS["auth_refresh"])
async def refresh_token(request: Request, token_data: TokenRefresh, db: Session = Depends(get_db)):
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


@router.post("/supabase/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_supabase_email(payload: SupabaseEmailConfirmRequest):
    """Mark a Supabase user's email as confirmed using the service role."""
    try:
        updated = supabase.confirm_user_email(payload.email)
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Supabase user not found")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Supabase email confirmation failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to confirm Supabase email")


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


@router.post("/forgot-password", status_code=status.HTTP_200_OK)
@limiter.limit(RATE_LIMITS["auth_forgot_password"] if "auth_forgot_password" in RATE_LIMITS else "5/hour")
async def forgot_password(
    request: Request,
    forgot_data: ForgotPasswordRequest,
    db: Session = Depends(get_db)
):
    """
    Request password reset
    
    - Validates email exists
    - Generates reset token
    - Sends reset email (simulated for now)
    - Returns success message (doesn't reveal if email exists for security)
    """
    client_ip = request.client.host if request.client else "unknown"
    try:
        email = forgot_data.email.strip().lower()
        
        # Find user by email
        user = db.query(User).filter(User.email == email).first()
        
        # Always return success to prevent email enumeration
        if not user:
            logger.info(f"Password reset requested for non-existent email: {email}")
            return {"message": "If an account with that email exists, a password reset link has been sent."}
        
        # Generate secure reset token
        reset_token = secrets.token_urlsafe(32)
        
        # Set token and expiration (1 hour)
        user.reset_token = reset_token  # type: ignore
        user.reset_token_expires = utc_now() + timedelta(hours=1)  # type: ignore
        db.commit()
        
        # TODO: Send email with reset link
        # For now, just log it (in production, use email service)
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
        logger.info(f"Password reset requested for: {email}")
        logger.info(f"Reset link (dev only): {reset_link}")
        
        # In production, you would send an email here:
        # await send_password_reset_email(user.email, reset_link)
        
        return {"message": "If an account with that email exists, a password reset link has been sent."}
        
    except Exception as e:
        logger.error(f"Failed to process password reset request: {e}")
        db.rollback()
        # Still return success to prevent information leakage
        return {"message": "If an account with that email exists, a password reset link has been sent."}


@router.post("/reset-password", status_code=status.HTTP_200_OK)
@limiter.limit(RATE_LIMITS["auth_reset_password"] if "auth_reset_password" in RATE_LIMITS else "10/hour")
async def reset_password(
    request: Request,
    reset_data: ResetPasswordRequest,
    db: Session = Depends(get_db)
):
    """
    Reset password using token
    
    - Validates reset token
    - Checks token expiration
    - Updates password
    - Clears reset token
    """
    try:
        # Find user by reset token
        user = db.query(User).filter(User.reset_token == reset_data.token).first()
        
        if not user:
            raise AuthenticationException("Invalid or expired reset token")
        
        # Check if token has expired
        if not user.reset_token_expires or user.reset_token_expires < utc_now():  # type: ignore
            # Clear expired token
            user.reset_token = None  # type: ignore
            user.reset_token_expires = None  # type: ignore
            db.commit()
            raise AuthenticationException("Reset token has expired. Please request a new password reset.")
        
        # Hash and update new password
        user.hashed_password = security_manager.hash_password(reset_data.new_password)  # type: ignore
        
        # Clear reset token
        user.reset_token = None  # type: ignore
        user.reset_token_expires = None  # type: ignore
        
        # Reset failed login attempts
        user.failed_login_attempts = 0  # type: ignore
        user.locked_until = None  # type: ignore
        
        user.updated_at = utc_now()  # type: ignore
        db.commit()
        
        logger.info(f"Password reset successfully for user: {user.email}")
        
        return {"message": "Password has been reset successfully. You can now log in with your new password."}
        
    except AuthenticationException:
        raise
    except ValidationException:
        raise
    except Exception as e:
        logger.error(f"Failed to reset password: {e}")
        db.rollback()
        raise DatabaseException("Failed to reset password")
