"""
Report model for Sentinel.

This model tracks generated PDF security reports.
Each report is associated with a scan and can be downloaded by users.
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
    from app.db.models.scan import Scan


class Report(Base):
    """
    Report model.

    Tracks generated PDF security reports.

    Attributes:
        id: Unique UUID identifier
        scan_id: ID of the scan the report is based on
        website_id: ID of the website (denormalized for faster queries)
        user_id: ID of the user who generated the report
        title: Report title
        description: Report description
        file_path: Path to the stored PDF file
        file_size: Size of the PDF file in bytes
        file_hash: Hash of the file for integrity verification
        format: Report format (pdf, html, docx)
        status: Report status (generating, completed, failed)
        template_version: Version of the report template used
        sections: JSON array of included sections
        settings: JSON report generation settings
        download_count: Number of times the report was downloaded
        last_download_at: Timestamp of the last download
        expires_at: Timestamp when the report expires
        error_message: Error message if generation failed
        metadata: Additional metadata as JSON
        created_at: Creation timestamp
        updated_at: Last update timestamp
        completed_at: Completion timestamp
    """

    __tablename__ = "reports"

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
        unique=True,  # One report per scan
        index=True,
    )

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
    # Report Information
    # ================================================================

    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # ================================================================
    # File Information
    # ================================================================

    file_path: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    file_size: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    file_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )

    # ================================================================
    # Format & Template
    # ================================================================

    format: Mapped[str] = mapped_column(
        Enum(
            "pdf",
            "html",
            "docx",
            name="report_format"
        ),
        nullable=False,
        default="pdf",
        server_default="pdf",
    )

    template_version: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="1.0",
        server_default="1.0",
    )

    # ================================================================
    # Status
    # ================================================================

    status: Mapped[str] = mapped_column(
        Enum(
            "generating",
            "completed",
            "failed",
            name="report_status"
        ),
        nullable=False,
        default="generating",
        server_default="generating",
        index=True,
    )

    # ================================================================
    # Content Configuration
    # ================================================================

    sections: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
    )

    settings: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    # ================================================================
    # Download Tracking
    # ================================================================

    download_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    last_download_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ================================================================
    # Expiration
    # ================================================================

    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # ================================================================
    # Error Handling
    # ================================================================

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # ================================================================
    # Metadata
    # ================================================================

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

    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ================================================================
    # Indexes
    # ================================================================

    __table_args__ = (
        Index("ix_reports_scan_id", "scan_id"),
        Index("ix_reports_website_id", "website_id"),
        Index("ix_reports_user_id", "user_id"),
        Index("ix_reports_status", "status"),
        Index("ix_reports_created_at", "created_at"),
        Index("ix_reports_expires_at", "expires_at"),
        Index("ix_reports_website_status", "website_id", "status"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="reports",
        lazy="selectin",
    )

    website: Mapped["Website"] = relationship(
        "Website",
        back_populates="reports",
        lazy="selectin",
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="reports",
        lazy="selectin",
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def is_completed(self) -> bool:
        """Check if report is completed."""
        return self.status == "completed"

    @property
    def is_generating(self) -> bool:
        """Check if report is generating."""
        return self.status == "generating"

    @property
    def is_failed(self) -> bool:
        """Check if report generation failed."""
        return self.status == "failed"

    @property
    def is_available(self) -> bool:
        """Check if report is available for download."""
        return self.is_completed and self.file_path is not None

    @property
    def is_expired(self) -> bool:
        """Check if report has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    @property
    def file_size_display(self) -> str:
        """Get human-readable file size."""
        if self.file_size is None:
            return "Unknown"
        for unit in ["B", "KB", "MB", "GB"]:
            if self.file_size < 1024:
                return f"{self.file_size:.1f} {unit}"
            self.file_size /= 1024
        return f"{self.file_size:.1f} TB"

    # ================================================================
    # Helper Methods
    # ================================================================

    def mark_generating(self) -> None:
        """Mark report as generating."""
        self.status = "generating"

    def mark_completed(self, file_path: str, file_size: int, file_hash: str) -> None:
        """Mark report as completed."""
        self.status = "completed"
        self.file_path = file_path
        self.file_size = file_size
        self.file_hash = file_hash
        self.completed_at = datetime.utcnow()
        # Set expiry to 30 days by default
        if self.expires_at is None:
            self.expires_at = datetime.utcnow() + timedelta(days=30)

    def mark_failed(self, error: str) -> None:
        """Mark report as failed."""
        self.status = "failed"
        self.error_message = error
        self.completed_at = datetime.utcnow()

    def record_download(self) -> None:
        """Record a download event."""
        self.download_count += 1
        self.last_download_at = datetime.utcnow()

    def set_sections(self, sections: list) -> None:
        """Set the report sections."""
        self.sections = sections

    def set_settings(self, settings: dict) -> None:
        """Set the report generation settings."""
        self.settings = settings

    def set_expiry(self, days: int = 30) -> None:
        """Set report expiry date."""
        self.expires_at = datetime.utcnow() + timedelta(days=days)

    def get_section_titles(self) -> list:
        """Get list of section titles."""
        if self.sections:
            return [s.get("title", "Untitled") for s in self.sections if isinstance(s, dict)]
        return []

    def get_summary(self) -> dict:
        """
        Get a summary of the report.

        Returns:
            dict: Summary of the report.
        """
        return {
            "id": str(self.id),
            "scan_id": str(self.scan_id),
            "website_id": str(self.website_id),
            "title": self.title,
            "status": self.status,
            "format": self.format,
            "file_size_display": self.file_size_display,
            "is_available": self.is_available,
            "is_expired": self.is_expired,
            "download_count": self.download_count,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<Report(id={self.id}, scan_id={self.scan_id}, "
            f"status={self.status}, format={self.format})>"
        )

    def __str__(self) -> str:
        return f"Report for scan {self.scan_id} - {self.status}"


# Need to import timedelta at the top
from datetime import timedelta