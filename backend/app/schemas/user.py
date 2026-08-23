"""
User schemas for Sentinel.

Defines Pydantic models for user data validation and serialization.
"""

from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    """Schema for user registration."""

    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, description="User's password (min 8 characters)")
    full_name: str = Field(..., min_length=1, max_length=255, description="User's full name")


class UserRegister(BaseModel):
    """Schema for user registration (alias)."""

    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, description="User's password (min 8 characters)")
    full_name: str = Field(..., min_length=1, max_length=255, description="User's full name")


class UserUpdate(BaseModel):
    """Schema for updating a user."""

    email: Optional[EmailStr] = Field(None, description="User's email address")
    full_name: Optional[str] = Field(None, min_length=1, max_length=255, description="User's full name")
    password: Optional[str] = Field(None, min_length=8, description="New password")


class UserResponse(BaseModel):
    """Schema for user response."""

    id: UUID
    email: str
    full_name: str
    role: str
    is_active: bool
    is_email_verified: bool
    last_login_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """Schema for list of users response."""

    items: List[UserResponse]
    total: int
    skip: int
    limit: int


class UserLogin(BaseModel):
    """Schema for user login."""

    email: str = Field(..., description="User's email address")
    password: str = Field(..., description="User's password")


class TokenResponse(BaseModel):
    """Schema for token response."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int


class PasswordChange(BaseModel):
    """Schema for password change."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")


class PasswordResetRequest(BaseModel):
    """Schema for password reset request."""

    email: str = Field(..., description="User's email address")


class PasswordResetConfirm(BaseModel):
    """Schema for password reset confirmation."""

    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=8, description="New password")