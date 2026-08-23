"""
Scan schemas for Sentinel.

Defines Pydantic models for scan data validation and serialization.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    """Schema for creating a new scan."""

    scan_type: str = Field(default="full", description="Type of scan (full, quick, passive, custom)")


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""

    status: Optional[str] = Field(None, description="Scan status")
    score: Optional[int] = Field(None, description="Security score")
    error_message: Optional[str] = Field(None, description="Error message if failed")


class ScanResponse(BaseModel):
    """Schema for scan response."""

    id: UUID
    website_id: UUID
    user_id: UUID
    status: str
    scan_type: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[float]
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    score: Optional[int]
    summary: Optional[Dict[str, Any]]
    error_message: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Schema for list of scans response."""

    items: List[ScanResponse]
    total: int
    skip: int
    limit: int


class ScanStatusResponse(BaseModel):
    """Schema for scan status response."""

    id: UUID
    status: str
    progress: float
    started_at: Optional[str]
    completed_at: Optional[str]
    findings_count: int
    score: Optional[int]
    error_message: Optional[str]
    scan_type: str