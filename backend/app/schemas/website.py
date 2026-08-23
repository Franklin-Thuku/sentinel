"""
Website schemas for Sentinel.

Defines Pydantic models for website data validation and serialization.
"""

from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, Field, validator


class WebsiteCreate(BaseModel):
    """Schema for creating a website."""

    url: str = Field(..., description="Website URL")
    name: Optional[str] = Field(None, max_length=255, description="Website display name")
    description: Optional[str] = Field(None, description="Website description")
    organization_id: Optional[UUID] = Field(None, description="Organization ID")

    @validator("url")
    def validate_url(cls, v: str) -> str:
        """Validate URL format."""
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"
        return v


class WebsiteUpdate(BaseModel):
    """Schema for updating a website."""

    url: Optional[str] = Field(None, description="Website URL")
    name: Optional[str] = Field(None, max_length=255, description="Website display name")
    description: Optional[str] = Field(None, description="Website description")
    is_active: Optional[bool] = Field(None, description="Whether the website is active")


class WebsiteResponse(BaseModel):
    """Schema for website response."""

    id: UUID
    user_id: UUID
    organization_id: Optional[UUID]
    url: str
    name: str
    description: Optional[str]
    is_verified: bool
    is_active: bool
    last_scanned_at: Optional[datetime]
    last_score: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class WebsiteListResponse(BaseModel):
    """Schema for list of websites response."""

    items: List[WebsiteResponse]
    total: int
    skip: int
    limit: int


class WebsiteVerifyRequest(BaseModel):
    """Schema for website verification request."""

    method: str = Field(default="dns_txt", description="Verification method (dns_txt, http_file, meta_tag)")


class WebsiteVerifyResponse(BaseModel):
    """Schema for website verification response."""

    verified: bool
    message: str
    verification_id: Optional[UUID] = None
    method: Optional[str] = None
    attempts: Optional[int] = None
    instructions: Optional[dict] = None