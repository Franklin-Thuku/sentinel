"""
Report schemas for Sentinel.

Defines Pydantic models for report data validation and serialization.
"""

from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, Field


class ReportGenerateRequest(BaseModel):
    """Schema for report generation request."""

    format: str = Field(default="pdf", description="Report format (pdf, html)")
    include_ai_analysis: bool = Field(default=True, description="Include AI analysis in report")


class ReportResponse(BaseModel):
    """Schema for report response."""

    id: UUID
    scan_id: UUID
    website_id: UUID
    user_id: UUID
    title: str
    description: Optional[str]
    file_path: Optional[str]
    file_size: Optional[int]
    format: str
    status: str
    download_count: int
    last_download_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    """Schema for list of reports response."""

    items: List[ReportResponse]
    total: int
    skip: int
    limit: int