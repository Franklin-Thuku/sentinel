"""
Finding schemas for Sentinel.

Defines Pydantic models for finding data validation and serialization.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field


class FindingResponse(BaseModel):
    """Schema for finding response."""

    id: UUID
    scan_id: UUID
    website_id: UUID
    category: str
    severity: str
    title: str
    description: str
    evidence: Optional[str]
    affected_url: Optional[str]
    remediation: Optional[str]
    confidence: float
    references: Optional[List[str]]
    status: str
    scanner_module: Optional[str]
    metadata: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    """Schema for updating a finding."""

    status: Optional[str] = Field(None, description="Finding status (open, acknowledged, resolved, false_positive, wont_fix)")
    remediation: Optional[str] = Field(None, description="Remediation recommendation")


class FindingListResponse(BaseModel):
    """Schema for list of findings response."""

    items: List[FindingResponse]
    total: int
    skip: int
    limit: int