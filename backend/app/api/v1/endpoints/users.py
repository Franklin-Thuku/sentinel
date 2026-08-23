"""
User endpoints.

Handles user management: get current user, update profile, change password.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_active_user, get_current_admin_user
from app.schemas.user import UserUpdate, PasswordChange, UserResponse, UserListResponse
from app.services.user_service import UserService
from app.db.models.user import User

router = APIRouter()


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """
    Get the current authenticated user's information.

    Args:
        current_user: The authenticated user.

    Returns:
        User: The current user.
    """
    return current_user


@router.put(
    "/me",
    response_model=UserResponse,
    summary="Update current user",
)
async def update_current_user(
    update_data: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> User:
    """
    Update the current user's profile.

    Args:
        update_data: Update data.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        User: The updated user.
    """
    service = UserService(db)
    user = service.update_user_profile(current_user.id, update_data)
    return user


@router.post(
    "/me/change-password",
    response_model=dict,
    summary="Change password",
)
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Change the current user's password.

    Args:
        password_data: Current and new password.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Success message.
    """
    service = UserService(db)
    service.change_password(current_user.id, password_data)
    return {"message": "Password changed successfully"}


@router.post(
    "/me/verify-email",
    response_model=dict,
    summary="Verify email",
)
async def verify_email(
    token: str,
    db: Session = Depends(get_db),
) -> dict:
    """
    Verify user's email using verification token.

    Args:
        token: Email verification token.
        db: Database session.

    Returns:
        dict: Success message.
    """
    from app.core.security import verify_email_verification_token

    email = verify_email_verification_token(token)

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )

    service = UserService(db)
    user = service.get_user_by_email(email)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.is_email_verified:
        return {"message": "Email already verified"}

    user.is_email_verified = True
    user.email_verified_at = datetime.utcnow()
    db.commit()

    return {"message": "Email verified successfully"}


@router.post(
    "/me/resend-verification",
    response_model=dict,
    summary="Resend verification email",
)
async def resend_verification_email(
    current_user: User = Depends(get_current_active_user),
) -> dict:
    """
    Resend email verification link.

    Args:
        current_user: The authenticated user.

    Returns:
        dict: Success message.
    """
    if current_user.is_email_verified:
        return {"message": "Email already verified"}

    # Create verification token
    from app.core.security import create_email_verification_token

    token = create_email_verification_token(current_user.email)

    # In production, send email here
    # For now, return the token for testing
    return {
        "message": "Verification email sent",
        "token": token,  # Remove in production
    }


@router.delete(
    "/me",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete account",
)
async def delete_account(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> None:
    """
    Delete the current user's account (soft delete).

    Args:
        current_user: The authenticated user.
        db: Database session.
    """
    service = UserService(db)
    service.soft_delete_user(current_user.id)


@router.get(
    "/",
    response_model=UserListResponse,
    summary="List users",
    description="Admin only - list all users",
)
async def list_users(
    skip: int = 0,
    limit: int = 20,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> UserListResponse:
    """
    List all users (admin only).

    Args:
        skip: Number of records to skip.
        limit: Maximum records to return.
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        UserListResponse: List of users with pagination info.
    """
    users = db.query(User).filter(
        User.deleted_at.is_(None)
    ).offset(skip).limit(limit).all()

    total = db.query(User).filter(
        User.deleted_at.is_(None)
    ).count()

    return UserListResponse(
        items=users,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user by ID",
    description="Admin only - get a specific user",
)
async def get_user_by_id(
    user_id: UUID,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> User:
    """
    Get a specific user by ID (admin only).

    Args:
        user_id: ID of the user.
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        User: The user.

    Raises:
        HTTPException: If user not found.
    """
    service = UserService(db)
    user = service.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user


@router.put(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update user",
    description="Admin only - update a user",
)
async def update_user_by_admin(
    user_id: UUID,
    update_data: UserUpdate,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> User:
    """
    Update a user (admin only).

    Args:
        user_id: ID of the user.
        update_data: Update data.
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        User: The updated user.
    """
    service = UserService(db)
    user = service.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user = service.update_user_profile(user_id, update_data)
    return user


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user",
    description="Admin only - delete a user",
)
async def delete_user_by_admin(
    user_id: UUID,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> None:
    """
    Delete a user (admin only).

    Args:
        user_id: ID of the user.
        admin_user: The authenticated admin user.
        db: Database session.
    """
    service = UserService(db)
    service.soft_delete_user(user_id)


@router.post(
    "/{user_id}/reactivate",
    response_model=UserResponse,
    summary="Reactivate user",
    description="Admin only - reactivate a soft-deleted user",
)
async def reactivate_user(
    user_id: UUID,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> User:
    """
    Reactivate a soft-deleted user (admin only).

    Args:
        user_id: ID of the user.
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        User: The reactivated user.
    """
    service = UserService(db)
    user = service.reactivate_user(user_id)
    return user


@router.get(
    "/me/stats",
    response_model=dict,
    summary="Get user statistics",
)
async def get_user_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get statistics for the current user.

    Args:
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: User statistics.
    """
    service = UserService(db)
    stats = service.get_user_stats(current_user.id)
    return stats


# Need to import datetime
from datetime import datetime