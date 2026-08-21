"""
Scan Job model for Sentinel.

This model tracks individual background jobs that make up a scan.
A single scan can consist of multiple jobs (e.g., headers, TLS, DNS).
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Integer,
    Text,
    Enum,
    Index,
    func,
    ForeignKey,
    Float,
    JSON,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# ================================================================
# TYPE_CHECKING: Avoid circular import errors
# ================================================================

if TYPE_CHECKING:
    from app.db.models.scan import Scan


class ScanJob(Base):
    """
    Scan Job model.

    Tracks individual jobs/tasks that make up a scan.
    Each scan can have multiple jobs (one per scanner module).

    Attributes:
        id: Unique UUID identifier
        scan_id: ID of the parent scan
        job_type: Type of job (headers, tls, dns, cookies, etc.)
        status: Job status (pending, running, completed, failed)
        started_at: Timestamp when job started
        completed_at: Timestamp when job completed
        duration_seconds: Job duration in seconds
        findings_count: Number of findings from this job
        result: JSON result data from the job
        error_message: Error message if job failed
        retry_count: Number of retry attempts
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "scan_jobs"

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

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ================================================================
    # Job Information
    # ================================================================

    job_type: Mapped[str] = mapped_column(
        Enum(
            "headers",
            "tls",
            "dns",
            "cookies",
            "content",
            "robots",
            "sitemap",
            "technology",
            "passive",
            "configuration",
            "custom",
            name="scan_job_type"
        ),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        Enum(
            "pending",
            "running",
            "completed",
            "failed",
            "skipped",
            name="scan_job_status"
        ),
        nullable=False,
        default="pending",
        server_default="pending",
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
    # Results
    # ================================================================

    findings_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    result: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    # ================================================================
    # Error & Retry
    # ================================================================

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    retry_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
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
        Index("ix_scan_jobs_scan_status", "scan_id", "status"),
        Index("ix_scan_jobs_job_type", "job_type"),
        Index("ix_scan_jobs_status", "status"),
        Index("ix_scan_jobs_created_at", "created_at"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="jobs",
        lazy="selectin",
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def is_completed(self) -> bool:
        """Check if job is completed."""
        return self.status == "completed"

    @property
    def is_running(self) -> bool:
        """Check if job is currently running."""
        return self.status == "running"

    @property
    def is_failed(self) -> bool:
        """Check if job failed."""
        return self.status == "failed"

    @property
    def is_pending(self) -> bool:
        """Check if job is pending."""
        return self.status == "pending"

    @property
    def is_skipped(self) -> bool:
        """Check if job was skipped."""
        return self.status == "skipped"

    @property
    def has_result(self) -> bool:
        """Check if job has result data."""
        return self.result is not None

    # ================================================================
    # Helper Methods
    # ================================================================

    def start(self) -> None:
        """Mark job as started."""
        self.status = "running"
        self.started_at = datetime.utcnow()

    def complete(self, result: Optional[dict] = None) -> None:
        """Mark job as completed."""
        self.status = "completed"
        self.completed_at = datetime.utcnow()
        if self.started_at:
            self.duration_seconds = (self.completed_at - self.started_at).total_seconds()
        if result is not None:
            self.result = result

    def fail(self, error: str) -> None:
        """Mark job as failed."""
        self.status = "failed"
        self.completed_at = datetime.utcnow()
        self.error_message = error
        if self.started_at:
            self.duration_seconds = (self.completed_at - self.started_at).total_seconds()

    def skip(self, reason: Optional[str] = None) -> None:
        """Skip the job."""
        self.status = "skipped"
        if reason:
            self.error_message = reason

    def increment_retry(self) -> int:
        """Increment retry count and return new count."""
        self.retry_count += 1
        return self.retry_count

    def reset(self) -> None:
        """Reset job to pending state (for retry)."""
        self.status = "pending"
        self.started_at = None
        self.completed_at = None
        self.duration_seconds = None
        self.error_message = None

    def update_findings_count(self, count: int) -> None:
        """Update the findings count."""
        self.findings_count = count

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<ScanJob(id={self.id}, scan_id={self.scan_id}, "
            f"job_type={self.job_type}, status={self.status})>"
        )

    def __str__(self) -> str:
        return f"{self.job_type} job for scan {self.scan_id} - {self.status}"    