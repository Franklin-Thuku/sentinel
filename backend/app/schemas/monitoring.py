"""
Monitoring schemas for Sentinel.

Defines Pydantic models for monitoring configuration validation and serialization.
"""

from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, Field


class MonitoringConfigCreate(BaseModel):
    """Schema for creating a monitoring configuration."""

    frequency: str = Field(default="weekly", description="Frequency (daily, weekly, monthly, custom)")
    scan_type: str = Field(default="full", description="Scan type (full, quick, passive)")
    time_of_day: Optional[str] = Field(None, description="Time of day in HH:MM format")
    day_of_week: Optional[int] = Field(None, ge=0, le=6, description="Day of week (0=Monday, 6=Sunday)")
    day_of_month: Optional[int] = Field(None, ge=1, le=31, description="Day of month")
    notification_channels: Optional[List[str]] = Field(default=["email"], description="Notification channels")


class MonitoringConfigUpdate(BaseModel):
    """Schema for updating a monitoring configuration."""

    frequency: Optional[str] = Field(None, description="Frequency (daily, weekly, monthly, custom)")
    scan_type: Optional[str] = Field(None, description="Scan type (full, quick, passive)")
    time_of_day: Optional[str] = Field(None, description="Time of day in HH:MM format")
    day_of_week: Optional[int] = Field(None, ge=0, le=6, description="Day of week (0=Monday, 6=Sunday)")
    day_of_month: Optional[int] = Field(None, ge=1, le=31, description="Day of month")
    notification_channels: Optional[List[str]] = Field(None, description="Notification channels")
    is_active: Optional[bool] = Field(None, description="Whether monitoring is active")


class MonitoringConfigResponse(BaseModel):
    """Schema for monitoring configuration response."""

    id: UUID
    website_id: UUID
    user_id: UUID
    frequency: str
    scan_type: str
    time_of_day: Optional[str]
    day_of_week: Optional[int]
    day_of_month: Optional[int]
    timezone: str
    is_active: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    notification_channels: Optional[List[str]]
    failure_count: int
    max_failures: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MonitoringConfigListResponse(BaseModel):
    """Schema for list of monitoring configurations response."""

    items: List[MonitoringConfigResponse]
    total: int
    skip: int
    limit: int