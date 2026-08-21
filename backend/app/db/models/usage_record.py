"""
Usage Record model for Sentinel.

This model tracks usage metrics for billing and limit enforcement.
It records actual usage against subscription limits.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Integer,
    Enum,
    Index,
    func,
    ForeignKey,
    JSON,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# ================================================================
# TYPE_CHECKING: Avoid circular import errors
# ================================================================

if TYPE_CHECKING:
    from app.db.models.organization import Organization


class UsageRecord(Base):
    """
    Usage Record model.

    Tracks usage metrics for billing and limit enforcement.

    Attributes:
        id: Unique UUID identifier
        organization_id: ID of the organization
        metric: Usage metric type (websites, scans, ai_analysis, reports, monitoring_jobs)
        count: Amount of usage for this metric
        period_start: Start of the usage period
        period_end: End of the usage period
        reference_id: External reference ID to prevent double-counting
        metadata: Additional metadata as JSON
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "usage_records"

    # ================================================================
    # Primary Key
    # ================================================================

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # ================================================================
    # Foreign Keys
    # ================================================================

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ================================================================
    # Usage Information
    # ================================================================

    metric: Mapped[str] = mapped_column(
        Enum(
            "websites",
            "scans",
            "ai_analysis",
            "reports",
            "monitoring_jobs",
            "team_members",
            "storage",
            name="usage_metric"
        ),
        nullable=False,
        index=True,
    )

    count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    # ================================================================
    # Period
    # ================================================================

    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # ================================================================
    # Reference & Metadata
    # ================================================================

    reference_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    additional_metadata: Mapped[Optional[dict]] = mapped_column(
        "metadata",
        JSON,
        nullable=True,
    )

    # ================================================================
    # Timestamps
    # ================================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # ================================================================
    # Indexes
    # ================================================================

    __table_args__ = (
        Index("ix_usage_records_organization_id", "organization_id"),
        Index("ix_usage_records_metric", "metric"),
        Index("ix_usage_records_period", "period_start", "period_end"),
        Index("ix_usage_records_org_metric_period", "organization_id", "metric", "period_start"),
        Index("ix_usage_records_reference_id", "reference_id"),
        Index("ix_usage_records_created_at", "created_at"),
        Index("ix_usage_records_org_metric", "organization_id", "metric"),
        Index("ix_usage_records_org_period", "organization_id", "period_start"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="usage_records",
        lazy="selectin",
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def metric_display(self) -> str:
        """Get formatted metric name."""
        return {
            "websites": "Websites",
            "scans": "Scans",
            "ai_analysis": "AI Analysis",
            "reports": "Reports",
            "monitoring_jobs": "Monitoring Jobs",
            "team_members": "Team Members",
            "storage": "Storage",
        }.get(self.metric, self.metric.replace("_", " ").title())

    @property
    def period_display(self) -> str:
        """Get formatted period string."""
        return f"{self.period_start.strftime('%Y-%m-%d')} to {self.period_end.strftime('%Y-%m-%d')}"

    # ================================================================
    # Helper Methods
    # ================================================================

    def increment(self, amount: int = 1) -> None:
        """Increment usage count."""
        self.count += amount

    def set_count(self, count: int) -> None:
        """Set usage count."""
        self.count = count

    def is_within_period(self, date: datetime) -> bool:
        """Check if a date is within the usage period."""
        return self.period_start <= date <= self.period_end

    def get_period_usage(self) -> dict:
        """
        Get a summary of the usage record.

        Returns:
            dict: Summary of the usage record.
        """
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "metric": self.metric,
            "metric_display": self.metric_display,
            "count": self.count,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "period_display": self.period_display,
            "reference_id": self.reference_id,
            "created_at": self.created_at.isoformat(),
        }

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<UsageRecord(id={self.id}, organization_id={self.organization_id}, "
            f"metric={self.metric}, count={self.count})>"
        )

    def __str__(self) -> str:
        return f"{self.metric}: {self.count} ({self.period_display})"