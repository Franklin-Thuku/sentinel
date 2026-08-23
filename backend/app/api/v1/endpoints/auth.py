"""
Authentication API endpoints for Sentinel.

Handles user registration, login, token refresh, and logout.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.user import (
    UserRegister,
    UserResponse,
    TokenResponse,
)
from app.schemas.security import (
    RefreshTokenRequest,
    ChangePasswordRequest,
)
from app.services.user_service import UserService
from app.api.deps import get_current_user, get_current_active_user
from app.db.models.user import User

router = APIRouter()

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ================================================================
# Public Endpoints
# ================================================================

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Create a new user account with email, password, and full name."
)
async def register(
    user_data: UserRegister,
    db: Session = Depends(get_db),
):
    """
    Register a new user.

    Args:
        user_data: User registration data (email, password, full_name)
        db: Database session

    Returns:
        UserResponse: The created user
    """
    service = UserService(db)
    user = service.register_user(user_data)
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login",
    description="Authenticate user and return JWT tokens."
)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    Login user and return JWT tokens.

    Args:
        form_data: OAuth2 form data (username=email, password)
        db: Database session

    Returns:
        TokenResponse: Access token, refresh token, and user info
    """
    service = UserService(db)
    
    try:
        user = service.authenticate_user(form_data.username, form_data.password)
        tokens = service.create_user_tokens(user)
        
        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": tokens["token_type"],
            "expires_in": tokens["expires_in"],
            "user": user,
        }
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Login error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during login",
        )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Get a new access token using a refresh token."
)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    """
    Refresh access token.

    Args:
        refresh_data: Refresh token
        db: Database session

    Returns:
        TokenResponse: New access token
    """
    service = UserService(db)
    result = service.refresh_access_token(refresh_data.refresh_token)
    
    return {
        "access_token": result["access_token"],
        "refresh_token": None,  # We don't return a new refresh token
        "token_type": result["token_type"],
        "expires_in": result["expires_in"],
        "user": None,
    }


# ================================================================
# Protected Endpoints (Require Authentication)
# ================================================================

@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
    description="Get the currently authenticated user's profile."
)
async def get_me(
    current_user: User = Depends(get_current_user),
):
    """
    Get current authenticated user.

    Args:
        current_user: The authenticated user

    Returns:
        UserResponse: The user's profile
    """
    return current_user


@router.post(
    "/me/change-password",
    response_model=dict,
    summary="Change password",
    description="Change the current user's password."
)
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Change user password.

    Args:
        password_data: Current and new password
        current_user: The authenticated user
        db: Database session

    Returns:
        dict: Success message
    """
    service = UserService(db)
    service.change_password(current_user.id, password_data)
    return {"message": "Password updated successfully"}


@router.post(
    "/logout",
    response_model=dict,
    summary="Logout",
    description="Logout the current user."
)
async def logout(
    current_user: User = Depends(get_current_active_user),
):
    """
    Logout user.

    Args:
        current_user: The authenticated user

    Returns:
        dict: Success message
    """
    # Since we're using stateless JWT, we just return a success message.
    # The client should discard the token.
    return {"message": "Successfully logged out"}


@router.delete(
    "/me",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete account",
    description="Soft delete the current user's account."
)
async def delete_account(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Soft delete user account.

    Args:
        current_user: The authenticated user
        db: Database session
    """
    service = UserService(db)
    service.soft_delete_user(current_user.id)
    return None