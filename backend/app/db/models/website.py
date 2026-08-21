"""
Website model for Sentinel.

This model represents websites being monitored by Sentinel.
Each website belongs to a user and an organization.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Boolean,
    Text,
    Integer,
    Index,
    func,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# ================================================================
# TYPE_CHECKING: Avoid circular import errors
# ================================================================

if TYPE_CHECKING:
    from app.db.models.user import User
    from app.db.models.organization import Organization
    from app.db.models.scan import Scan
    from app.db.models.website_verification import WebsiteVerification
    from app.db.models.monitoring_config import MonitoringConfig
    from app.db.models.alert import Alert


class Website(Base):
    """
    Website model.

    Attributes:
        id: Unique UUID identifier
        user_id: ID of the user who owns this website
        organization_id: ID of the organization this website belongs to
        url: The website URL (e.g., https://example.com)
        name: Display name for the website
        description: Optional description
        is_verified: Whether ownership has been verified
        is_active: Whether monitoring is active
        last_scanned_at: Timestamp of the last scan
        last_score: Most recent security score
        created_at: Creation timestamp
        updated_at: Last update timestamp
        deleted_at: Soft delete timestamp
    """

    __tablename__ = "websites"

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

    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ================================================================
    # Website Information
    # ================================================================

    url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # ================================================================
    # Status
    # ================================================================

    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )

    # ================================================================
    # Scan & Score Information
    # ================================================================

    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_score: Mapped[Optional[int]] = mapped_column(
        Integer,
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
    # Soft Delete
    # ================================================================

    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # ================================================================
    # Indexes
    # ================================================================

    __table_args__ = (
        Index("ix_websites_user_active", "user_id", "is_active"),
        Index("ix_websites_organization_active", "organization_id", "is_active"),
        Index("ix_websites_verified", "is_verified"),
        Index("ix_websites_last_scanned", "last_scanned_at"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    user: Mapped["User"] = relationship(
        "User",
        back_populates="websites",
        lazy="selectin",
    )

    organization: Mapped[Optional["Organization"]] = relationship(
        "Organization",
        back_populates="websites",
        lazy="selectin",
    )

    verifications: Mapped[list["WebsiteVerification"]] = relationship(
        "WebsiteVerification",
        back_populates="website",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    scans: Mapped[list["Scan"]] = relationship(
        "Scan",
        back_populates="website",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    monitoring_configs: Mapped[list["MonitoringConfig"]] = relationship(
        "MonitoringConfig",
        back_populates="website",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        back_populates="website",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def is_deleted(self) -> bool:
        """Check if website is soft-deleted."""
        return self.deleted_at is not None

    @property
    def domain(self) -> str:
        """Extract domain from URL."""
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        return parsed.netloc or self.url

    @property
    def score_category(self) -> str:
        """Get the security score category."""
        if self.last_score is None:
            return "Unknown"
        elif self.last_score >= 90:
            return "Excellent"
        elif self.last_score >= 75:
            return "Good"
        elif self.last_score >= 50:
            return "Fair"
        elif self.last_score >= 30:
            return "Poor"
        else:
            return "Critical"

    # ================================================================
    # Helper Methods
    # ================================================================

    def soft_delete(self) -> None:
        """Soft delete the website."""
        self.deleted_at = datetime.utcnow()
        self.is_active = False

    def restore(self) -> None:
        """Restore a soft-deleted website."""
        self.deleted_at = None
        self.is_active = True

    def update_score(self, score: int) -> None:
        """Update the security score."""
        self.last_score = score
        self.last_scanned_at = datetime.utcnow()

    def mark_verified(self) -> None:
        """Mark the website as verified."""
        self.is_verified = True

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return f"<Website(id={self.id}, url={self.url}, user_id={self.user_id})>"

    def __str__(self) -> str:
        return self.name or self.url