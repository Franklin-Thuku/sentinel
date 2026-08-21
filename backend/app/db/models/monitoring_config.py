"""
Monitoring Config model for Sentinel.

This model stores scheduled scan configurations for continuous monitoring.
Users can configure daily, weekly, or monthly scans for their websites.
"""

import uuid
from datetime import datetime, time
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Boolean,
    Enum,
    Index,
    func,
    ForeignKey,
    Time,
    Integer,
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


class MonitoringConfig(Base):
    """
    Monitoring Config model.

    Stores configuration for scheduled scans on websites.

    Attributes:
        id: Unique UUID identifier
        website_id: ID of the website being monitored
        user_id: ID of the user who created this config
        frequency: Scan frequency (daily, weekly, monthly)
        interval: Custom interval in days (if frequency is custom)
        time_of_day: Time of day to run the scan (UTC)
        day_of_week: Day of week to run the scan (0=Monday, 6=Sunday)
        day_of_month: Day of month to run the scan (1-31)
        timezone: Timezone for schedule (e.g., 'America/New_York')
        is_active: Whether monitoring is active
        last_run_at: Timestamp of the last successful run
        next_run_at: Timestamp of the next scheduled run
        scan_type: Type of scan to run (full, quick, passive)
        scan_config: JSON with additional scan configuration
        notification_channels: JSON with notification preferences
        failure_count: Number of consecutive failures
        max_failures: Maximum failures before disabling
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "monitoring_configs"

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
    # Schedule Configuration
    # ================================================================

    frequency: Mapped[str] = mapped_column(
        Enum(
            "daily",
            "weekly",
            "monthly",
            "custom",
            name="monitoring_frequency"
        ),
        nullable=False,
        default="weekly",
        server_default="weekly",
    )

    interval: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    time_of_day: Mapped[Optional[time]] = mapped_column(
        Time,
        nullable=True,
    )

    day_of_week: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    day_of_month: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    timezone: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="UTC",
        server_default="UTC",
    )

    # ================================================================
    # Status
    # ================================================================

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )

    # ================================================================
    # Run Tracking
    # ================================================================

    last_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    next_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # ================================================================
    # Scan Configuration
    # ================================================================

    scan_type: Mapped[str] = mapped_column(
        Enum(
            "full",
            "quick",
            "passive",
            name="monitoring_scan_type"
        ),
        nullable=False,
        default="full",
        server_default="full",
    )

    scan_config: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    # ================================================================
    # Notifications
    # ================================================================

    notification_channels: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
    )

    # ================================================================
    # Failure Handling
    # ================================================================

    failure_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    max_failures: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
        server_default="3",
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
        Index("ix_monitoring_configs_website_id", "website_id"),
        Index("ix_monitoring_configs_user_id", "user_id"),
        Index("ix_monitoring_configs_next_run", "next_run_at"),
        Index("ix_monitoring_configs_active", "is_active"),
        Index("ix_monitoring_configs_frequency", "frequency"),
        Index("ix_monitoring_configs_website_active", "website_id", "is_active"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    website: Mapped["Website"] = relationship(
        "Website",
        back_populates="monitoring_configs",
        lazy="selectin",
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="monitoring_configs",
        lazy="selectin",
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def is_daily(self) -> bool:
        """Check if monitoring is daily."""
        return self.frequency == "daily"

    @property
    def is_weekly(self) -> bool:
        """Check if monitoring is weekly."""
        return self.frequency == "weekly"

    @property
    def is_monthly(self) -> bool:
        """Check if monitoring is monthly."""
        return self.frequency == "monthly"

    @property
    def is_custom(self) -> bool:
        """Check if monitoring is custom."""
        return self.frequency == "custom"

    @property
    def is_failed(self) -> bool:
        """Check if monitoring has failed."""
        return self.failure_count >= self.max_failures

    @property
    def is_disabled(self) -> bool:
        """Check if monitoring is disabled."""
        return not self.is_active or self.is_failed

    @property
    def next_run_display(self) -> str:
        """Get formatted next run time."""
        if self.next_run_at:
            return self.next_run_at.strftime("%Y-%m-%d %H:%M %Z")
        return "Not scheduled"

    @property
    def frequency_display(self) -> str:
        """Get formatted frequency string."""
        if self.is_daily:
            return "Daily"
        elif self.is_weekly:
            days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
            if self.day_of_week is not None and 0 <= self.day_of_week < 7:
                return f"Weekly on {days[self.day_of_week]}"
            return "Weekly"
        elif self.is_monthly:
            if self.day_of_month:
                return f"Monthly on day {self.day_of_month}"
            return "Monthly"
        elif self.is_custom:
            return f"Every {self.interval} days"
        return "Unknown"

    # ================================================================
    # Helper Methods
    # ================================================================

    def enable(self) -> None:
        """Enable monitoring."""
        self.is_active = True
        self.failure_count = 0

    def disable(self) -> None:
        """Disable monitoring."""
        self.is_active = False

    def record_success(self) -> None:
        """Record a successful run."""
        self.last_run_at = datetime.utcnow()
        self.failure_count = 0

    def record_failure(self) -> None:
        """Record a failed run."""
        self.failure_count += 1
        if self.failure_count >= self.max_failures:
            self.is_active = False

    def update_next_run(self, next_run: datetime) -> None:
        """Update the next run time."""
        self.next_run_at = next_run

    def set_schedule(
        self,
        frequency: str,
        time_of_day: Optional[time] = None,
        day_of_week: Optional[int] = None,
        day_of_month: Optional[int] = None,
        interval: Optional[int] = None,
    ) -> None:
        """
        Set the monitoring schedule.

        Args:
            frequency: daily, weekly, monthly, custom
            time_of_day: Time of day to run (UTC)
            day_of_week: Day of week (0=Monday, 6=Sunday) for weekly
            day_of_month: Day of month (1-31) for monthly
            interval: Number of days between scans for custom
        """
        self.frequency = frequency
        self.time_of_day = time_of_day
        self.day_of_week = day_of_week
        self.day_of_month = day_of_month
        self.interval = interval

    def get_notification_channels(self) -> list:
        """Get notification channels."""
        if self.notification_channels:
            return self.notification_channels
        return ["email"]

    def add_notification_channel(self, channel: str) -> None:
        """Add a notification channel."""
        if self.notification_channels is None:
            self.notification_channels = []
        if channel not in self.notification_channels:
            self.notification_channels.append(channel)

    def remove_notification_channel(self, channel: str) -> None:
        """Remove a notification channel."""
        if self.notification_channels and channel in self.notification_channels:
            self.notification_channels.remove(channel)

    def get_summary(self) -> dict:
        """
        Get a summary of the monitoring configuration.

        Returns:
            dict: Summary of the configuration.
        """
        return {
            "id": str(self.id),
            "website_id": str(self.website_id),
            "frequency": self.frequency,
            "frequency_display": self.frequency_display,
            "is_active": self.is_active,
            "is_disabled": self.is_disabled,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "next_run_at": self.next_run_at.isoformat() if self.next_run_at else None,
            "scan_type": self.scan_type,
            "failure_count": self.failure_count,
            "max_failures": self.max_failures,
        }

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<MonitoringConfig(id={self.id}, website_id={self.website_id}, "
            f"frequency={self.frequency}, is_active={self.is_active})>"
        )

    def __str__(self) -> str:
        return f"Monitoring {self.frequency} for website {self.website_id}"