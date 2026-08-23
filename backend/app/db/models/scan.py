"""
Scan model for Sentinel.

This model represents security scan jobs executed against websites.
Each scan belongs to a website and user, and produces findings.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Integer,
    Text,
    Float,
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
    from app.db.models.user import User
    from app.db.models.website import Website
    from app.db.models.scan_job import ScanJob
    from app.db.models.finding import Finding
    from app.db.models.security_score import SecurityScore
    from app.db.models.report import Report
    from app.db.models.alert import Alert
    from app.db.models.ai_analysis import AIAnalysis


class Scan(Base):
    """
    Scan model.

    Tracks individual scan executions against a website.

    Attributes:
        id: Unique UUID identifier
        website_id: ID of the website being scanned
        user_id: ID of the user who initiated the scan
        status: Scan status (queued, running, completed, failed, cancelled)
        scan_type: Type of scan (full, quick, passive, custom)
        started_at: Timestamp when scan started
        completed_at: Timestamp when scan completed
        duration_seconds: Total scan duration in seconds
        findings_count: Total number of findings discovered
        critical_count: Number of critical findings
        high_count: Number of high severity findings
        medium_count: Number of medium severity findings
        low_count: Number of low severity findings
        info_count: Number of informational findings
        score: Overall security score (0-100)
        summary: JSON summary of scan results
        error_message: Error message if scan failed
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "scans"

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

    website_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ================================================================
    # Scan Information
    # ================================================================

    status: Mapped[str] = mapped_column(
        Enum(
            "queued",
            "running",
            "completed",
            "failed",
            "cancelled",
            name="scan_status"
        ),
        nullable=False,
        default="queued",
        server_default="queued",
    )

    scan_type: Mapped[str] = mapped_column(
        Enum(
            "full",
            "quick",
            "passive",
            "custom",
            name="scan_type"
        ),
        nullable=False,
        default="full",
        server_default="full",
    )

    # ================================================================
    # Timing Information
    # ================================================================

    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    duration_seconds: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )

    # ================================================================
    # Findings Counts
    # ================================================================

    findings_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    critical_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    high_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    medium_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    low_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    info_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    # ================================================================
    # Score
    # ================================================================

    score: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    # ================================================================
    # Summary & Errors
    # ================================================================

    summary: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # ================================================================
    # Timestamps
    # ================================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
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
        Index("ix_scans_website_status", "website_id", "status"),
        Index("ix_scans_user_created", "user_id", "created_at"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_created_at", "created_at"),
        Index("ix_scans_score", "score"),
    )

    # ================================================================
    # Relationships (All commented out until models exist)
    # ================================================================

    # website: Mapped["Website"] = relationship(
    #     "Website",
    #     back_populates="scans",
    #     lazy="selectin",
    # )

    # user: Mapped["User"] = relationship(
    #     "User",
    #     back_populates="scans",
    #     lazy="selectin",
    # )

    # jobs: Mapped[list["ScanJob"]] = relationship(
    #     "ScanJob",
    #     back_populates="scan",
    #     lazy="selectin",
    #     cascade="all, delete-orphan",
    # )

    # findings: Mapped[list["Finding"]] = relationship(
    #     "Finding",
    #     back_populates="scan",
    #     lazy="selectin",
    #     cascade="all, delete-orphan",
    # )

    # security_scores: Mapped[list["SecurityScore"]] = relationship(
    #     "SecurityScore",
    #     back_populates="scan",
    #     lazy="selectin",
    #     cascade="all, delete-orphan",
    # )

    # reports: Mapped[list["Report"]] = relationship(
    #     "Report",
    #     back_populates="scan",
    #     lazy="selectin",
    #     cascade="all, delete-orphan",
    # )

    # alerts: Mapped[list["Alert"]] = relationship(
    #     "Alert",
    #     back_populates="scan",
    #     lazy="selectin",
    #     cascade="all, delete-orphan",
    # )

    # ai_analyses: Mapped[list["AIAnalysis"]] = relationship(
    #     "AIAnalysis",
    #     back_populates="scan",
    #     lazy="selectin",
    #     cascade="all, delete-orphan",
    # )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def is_completed(self) -> bool:
        """Check if scan is completed."""
        return self.status == "completed"

    @property
    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self.status == "running"

    @property
    def is_failed(self) -> bool:
        """Check if scan failed."""
        return self.status == "failed"

    @property
    def is_queued(self) -> bool:
        """Check if scan is queued."""
        return self.status == "queued"

    @property
    def is_cancelled(self) -> bool:
        """Check if scan was cancelled."""
        return self.status == "cancelled"

    @property
    def has_findings(self) -> bool:
        """Check if scan has any findings."""
        return self.findings_count > 0

    @property
    def has_critical_findings(self) -> bool:
        """Check if scan has critical findings."""
        return self.critical_count > 0

    @property
    def score_category(self) -> str:
        """Get the security score category."""
        if self.score is None:
            return "Unknown"
        elif self.score >= 90:
            return "Excellent"
        elif self.score >= 75:
            return "Good"
        elif self.score >= 50:
            return "Fair"
        elif self.score >= 30:
            return "Poor"
        else:
            return "Critical"

    # ================================================================
    # Helper Methods
    # ================================================================

    def start(self) -> None:
        """Mark scan as started."""
        self.status = "running"
        self.started_at = datetime.utcnow()

    def complete(self) -> None:
        """Mark scan as completed."""
        self.status = "completed"
        self.completed_at = datetime.utcnow()
        if self.started_at:
            self.duration_seconds = (self.completed_at - self.started_at).total_seconds()

    def fail(self, error: str) -> None:
        """Mark scan as failed."""
        self.status = "failed"
        self.completed_at = datetime.utcnow()
        self.error_message = error
        if self.started_at:
            self.duration_seconds = (self.completed_at - self.started_at).total_seconds()

    def cancel(self) -> None:
        """Cancel the scan."""
        self.status = "cancelled"
        self.completed_at = datetime.utcnow()
        if self.started_at:
            self.duration_seconds = (self.completed_at - self.started_at).total_seconds()

    def update_findings_counts(self, counts: dict) -> None:
        """
        Update finding counts.

        Args:
            counts: Dictionary with keys: critical, high, medium, low, info
        """
        self.critical_count = counts.get("critical", 0)
        self.high_count = counts.get("high", 0)
        self.medium_count = counts.get("medium", 0)
        self.low_count = counts.get("low", 0)
        self.info_count = counts.get("info", 0)
        self.findings_count = sum([
            self.critical_count,
            self.high_count,
            self.medium_count,
            self.low_count,
            self.info_count,
        ])

    def update_score(self, score: int) -> None:
        """Update the security score."""
        self.score = score

    def update_summary(self, summary: dict) -> None:
        """Update the scan summary."""
        self.summary = summary

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<Scan(id={self.id}, website_id={self.website_id}, "
            f"status={self.status}, score={self.score})>"
        )

    def __str__(self) -> str:
        return f"Scan for {self.website_id} - {self.status}"