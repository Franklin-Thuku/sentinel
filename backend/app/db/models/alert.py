"""
Alert model for Sentinel.

This model stores security alerts generated for users.
Alerts are triggered by new findings, score changes, or monitoring events.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Boolean,
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


class Alert(Base):
    """
    Alert model.

    Stores security alerts generated for users.

    Attributes:
        id: Unique UUID identifier
        user_id: ID of the user receiving the alert
        website_id: ID of the website the alert is about
        scan_id: ID of the scan that triggered the alert (if applicable)
        type: Alert type (finding, score_change, scan_failed, etc.)
        severity: Alert severity (critical, high, medium, low, info)
        title: Alert title
        description: Alert description
        details: Additional details as JSON
        is_read: Whether the alert has been read
        is_dismissed: Whether the alert has been dismissed
        action_url: URL for the action to take
        action_label: Label for the action button
        triggered_at: Timestamp when the alert was triggered
        read_at: Timestamp when the alert was read
        dismissed_at: Timestamp when the alert was dismissed
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "alerts"

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

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    website_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("websites.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ================================================================
    # Alert Information
    # ================================================================

    type: Mapped[str] = mapped_column(
        Enum(
            "finding_critical",
            "finding_high",
            "finding_new",
            "score_change",
            "score_drop",
            "scan_failed",
            "scan_completed",
            "verification_required",
            "verification_expired",
            "monitoring_disabled",
            "system",
            name="alert_type"
        ),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        Enum(
            "critical",
            "high",
            "medium",
            "low",
            "info",
            name="alert_severity"
        ),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    details: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    # ================================================================
    # Status
    # ================================================================

    is_read: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        index=True,
    )

    is_dismissed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        index=True,
    )

    # ================================================================
    # Action
    # ================================================================

    action_url: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    action_label: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    # ================================================================
    # Timestamps
    # ================================================================

    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    read_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    dismissed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

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
        Index("ix_alerts_user_read", "user_id", "is_read"),
        Index("ix_alerts_user_dismissed", "user_id", "is_dismissed"),
        Index("ix_alerts_user_unread", "user_id", "is_read"),
        Index("ix_alerts_website_id", "website_id"),
        Index("ix_alerts_scan_id", "scan_id"),
        Index("ix_alerts_type", "type"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_triggered_at", "triggered_at"),
        Index("ix_alerts_user_unread_dismissed", "user_id", "is_read", "is_dismissed"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    user: Mapped["User"] = relationship(
        "User",
        back_populates="alerts",
        lazy="selectin",
    )

    website: Mapped[Optional["Website"]] = relationship(
        "Website",
        back_populates="alerts",
        lazy="selectin",
    )

    scan: Mapped[Optional["Scan"]] = relationship(
        "Scan",
        back_populates="alerts",
        lazy="selectin",
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def is_critical(self) -> bool:
        """Check if alert is critical severity."""
        return self.severity == "critical"

    @property
    def is_high(self) -> bool:
        """Check if alert is high severity."""
        return self.severity == "high"

    @property
    def is_medium(self) -> bool:
        """Check if alert is medium severity."""
        return self.severity == "medium"

    @property
    def is_low(self) -> bool:
        """Check if alert is low severity."""
        return self.severity == "low"

    @property
    def is_info(self) -> bool:
        """Check if alert is informational."""
        return self.severity == "info"

    @property
    def is_unread(self) -> bool:
        """Check if alert is unread."""
        return not self.is_read

    @property
    def is_active(self) -> bool:
        """Check if alert is active (not read and not dismissed)."""
        return not self.is_read and not self.is_dismissed

    @property
    def severity_color(self) -> str:
        """Get severity color for UI."""
        return {
            "critical": "red-600",
            "high": "orange-500",
            "medium": "yellow-500",
            "low": "blue-400",
            "info": "gray-400",
        }.get(self.severity, "gray-400")

    @property
    def severity_icon(self) -> str:
        """Get severity icon for UI."""
        return {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "ℹ️",
        }.get(self.severity, "⚪")

    @property
    def time_ago(self) -> str:
        """Get human-readable time since alert was triggered."""
        delta = datetime.utcnow() - self.triggered_at
        seconds = delta.total_seconds()

        if seconds < 60:
            return f"{int(seconds)}s ago"
        elif seconds < 3600:
            return f"{int(seconds / 60)}m ago"
        elif seconds < 86400:
            return f"{int(seconds / 3600)}h ago"
        elif seconds < 604800:
            return f"{int(seconds / 86400)}d ago"
        else:
            return self.triggered_at.strftime("%b %d, %Y")

    # ================================================================
    # Helper Methods
    # ================================================================

    def mark_read(self) -> None:
        """Mark alert as read."""
        self.is_read = True
        self.read_at = datetime.utcnow()

    def mark_unread(self) -> None:
        """Mark alert as unread."""
        self.is_read = False
        self.read_at = None

    def dismiss(self) -> None:
        """Dismiss the alert."""
        self.is_dismissed = True
        self.dismissed_at = datetime.utcnow()

    def restore(self) -> None:
        """Restore a dismissed alert."""
        self.is_dismissed = False
        self.dismissed_at = None

    def get_type_display(self) -> str:
        """Get formatted alert type."""
        type_display = {
            "finding_critical": "Critical Finding",
            "finding_high": "High Finding",
            "finding_new": "New Finding",
            "score_change": "Score Change",
            "score_drop": "Score Drop",
            "scan_failed": "Scan Failed",
            "scan_completed": "Scan Completed",
            "verification_required": "Verification Required",
            "verification_expired": "Verification Expired",
            "monitoring_disabled": "Monitoring Disabled",
            "system": "System Alert",
        }
        return type_display.get(self.type, self.type.replace("_", " ").title())

    def get_severity_display(self) -> str:
        """Get formatted severity string."""
        return self.severity.upper()

    def get_summary(self) -> dict:
        """
        Get a summary of the alert.

        Returns:
            dict: Summary of the alert.
        """
        return {
            "id": str(self.id),
            "type": self.type,
            "type_display": self.get_type_display(),
            "severity": self.severity,
            "severity_display": self.get_severity_display(),
            "title": self.title,
            "description": self.description,
            "is_read": self.is_read,
            "is_dismissed": self.is_dismissed,
            "is_active": self.is_active,
            "time_ago": self.time_ago,
            "triggered_at": self.triggered_at.isoformat(),
            "action_url": self.action_url,
            "action_label": self.action_label,
        }

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<Alert(id={self.id}, user_id={self.user_id}, "
            f"type={self.type}, severity={self.severity})>"
        )

    def __str__(self) -> str:
        return f"{self.severity.upper()}: {self.title}"