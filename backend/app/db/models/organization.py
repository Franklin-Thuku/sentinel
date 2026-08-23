"""
Organization model for Sentinel.

This model represents organizations (companies, agencies, teams)
that can have multiple users and websites.

Organizations enable:
- Multi-tenancy
- Agency/client management
- Team collaboration
- Shared billing
"""

import uuid
from datetime import datetime
from typing import Optional, List, Any, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Boolean,
    Text,
    Index,
    func,
    Table,
    Column,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# ================================================================
# TYPE_CHECKING: Avoid circular import errors
# ================================================================

if TYPE_CHECKING:
    from app.db.models.user import User
    from app.db.models.website import Website
    from app.db.models.subscription import Subscription
    from app.db.models.audit_log import AuditLog
    from app.db.models.usage_record import UsageRecord


# ================================================================
# Association Table: User <-> Organization (many-to-many)
# ================================================================

organization_users = Table(
    "organization_users",
    Base.metadata,
    Column(
        "organization_id",
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "user_id",
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "role",
        String(50),
        nullable=False,
        default="member",
        server_default="member",
    ),
    Column(
        "joined_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    ),
)


class Organization(Base):
    """
    Organization model.

    Attributes:
        id: Unique UUID identifier
        name: Organization name
        slug: URL-friendly unique identifier
        description: Optional description
        logo_url: Optional logo URL
        website: Optional organization website
        is_active: Whether the organization is active
        settings: JSON settings (billing, features, etc.)
        created_at: Creation timestamp
        updated_at: Last update timestamp
        deleted_at: Soft delete timestamp
    """

    __tablename__ = "organizations"

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
    # Organization Information
    # ================================================================

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    slug: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    logo_url: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    website: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
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
    # Settings (JSON)
    # ================================================================

    settings: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        default={},
        server_default="{}",
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
        Index("ix_organizations_slug_active", "slug", "is_active"),
        Index("ix_organizations_created_at", "created_at"),
    )

    # ================================================================
    # Relationships (using string names, resolved by TYPE_CHECKING)
    # ================================================================

    # Users belonging to this organization (many-to-many)
    users: Mapped[List["User"]] = relationship(
        "User",
        secondary=organization_users,
        back_populates="organizations",
        lazy="selectin",
    )

    # Websites owned by this organization
    websites: Mapped[List["Website"]] = relationship(
        "Website",
        back_populates="organization",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    # Subscriptions for this organization
    subscriptions: Mapped[List["Subscription"]] = relationship(
        "Subscription",
        back_populates="organization",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    # Audit logs for this organization
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="organization",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    # Usage records for this organization
    usage_records: Mapped[List["UsageRecord"]] = relationship(
        "UsageRecord",
        back_populates="organization",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    # ================================================================
    # Helper Methods
    # ================================================================

    @property
    def is_deleted(self) -> bool:
        """Check if organization is soft-deleted."""
        return self.deleted_at is not None

    def soft_delete(self) -> None:
        """Soft delete the organization."""
        self.deleted_at = datetime.utcnow()
        self.is_active = False

    def restore(self) -> None:
        """Restore a soft-deleted organization."""
        self.deleted_at = None
        self.is_active = True

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a setting value by key."""
        if not self.settings:
            return default
        return self.settings.get(key, default)

    def set_setting(self, key: str, value: Any) -> None:
        """Set a setting value."""
        if self.settings is None:
            self.settings = {}
        self.settings[key] = value

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return f"<Organization(id={self.id}, name={self.name}, slug={self.slug})>"

    def __str__(self) -> str:
        return self.name