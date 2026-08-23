"""
Alert schemas for Sentinel.

Defines Pydantic models for alert data validation and serialization.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field


class AlertResponse(BaseModel):
    """Schema for alert response."""

    id: UUID
    user_id: UUID
    website_id: Optional[UUID]
    scan_id: Optional[UUID]
    type: str
    severity: str
    title: str
    description: str
    details: Optional[Dict[str, Any]]
    is_read: bool
    is_dismissed: bool
    action_url: Optional[str]
    action_label: Optional[str]
    triggered_at: datetime
    read_at: Optional[datetime]
    dismissed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    """Schema for updating an alert."""

    is_read: Optional[bool] = Field(None, description="Mark as read/unread")
    is_dismissed: Optional[bool] = Field(None, description="Dismiss/restore alert")


class AlertListResponse(BaseModel):
    """Schema for list of alerts response."""

    items: List[AlertResponse]
    total: int
    skip: int
    limit: int