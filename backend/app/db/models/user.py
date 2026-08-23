"""
User model for Sentinel.

This model represents user accounts in the system.
All authentication, authorization, and user management
operations use this model.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    String,
    Index,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# ================================================================
# TYPE_CHECKING: Avoid circular import errors
# ================================================================

if TYPE_CHECKING:
    from app.db.models.website import Website
    from app.db.models.organization import Organization
    from app.db.models.scan import Scan
    from app.db.models.alert import Alert
    from app.db.models.monitoring_config import MonitoringConfig
    from app.db.models.audit_log import AuditLog
    from app.db.models.report import Report


class User(Base):
    """
    User account model.

    Attributes:
        id: Unique UUID identifier
        email: User's email address (unique, indexed)
        password_hash: Hashed password (bcrypt/argon2id)
        full_name: User's full name
        role: User role (user, admin, super_admin)
        is_active: Whether the account is active
        is_email_verified: Whether email has been verified
        email_verified_at: When email was verified
        last_login_at: Last login timestamp
        created_at: Account creation timestamp
        updated_at: Last update timestamp
        deleted_at: Soft delete timestamp (null if not deleted)
    """

    __tablename__ = "users"

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
    # User Information
    # ================================================================

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    full_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # ================================================================
    # User Role (for authorization)
    # ================================================================

    role: Mapped[str] = mapped_column(
        Enum("user", "admin", "super_admin", name="user_role"),
        nullable=False,
        default="user",
        server_default="user",
    )

    # ================================================================
    # Account Status
    # ================================================================

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )

    is_email_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    email_verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ================================================================
    # Login Tracking
    # ================================================================

    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
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
    # Indexes (Composite)
    # ================================================================

    __table_args__ = (
        Index("ix_users_email_active", "email", "is_active"),
        Index("ix_users_created_at", "created_at"),
        Index("ix_users_role", "role"),
    )

    # ================================================================
    # Relationships (using string names, resolved by TYPE_CHECKING)
    # ================================================================

    websites: Mapped[list["Website"]] = relationship(
        "Website",
        back_populates="user",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    organizations: Mapped[list["Organization"]] = relationship(
        "Organization",
        secondary="organization_users",
        back_populates="users",
        lazy="selectin",
    )

    scans: Mapped[list["Scan"]] = relationship(
        "Scan",
        back_populates="user",
        lazy="selectin",
    )

    alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        back_populates="user",
        lazy="selectin",
    )

    monitoring_configs: Mapped[list["MonitoringConfig"]] = relationship(
        "MonitoringConfig",
        back_populates="user",
        lazy="selectin",
    )

    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="user",
        lazy="selectin",
    )

    reports: Mapped[list["Report"]] = relationship(
        "Report",
        back_populates="user",
        lazy="selectin",
    )

    # ================================================================
    # Helper Methods
    # ================================================================

    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role in ("admin", "super_admin")

    @property
    def is_super_admin(self) -> bool:
        """Check if user has super_admin role."""
        return self.role == "super_admin"

    @property
    def is_deleted(self) -> bool:
        """Check if user account is soft-deleted."""
        return self.deleted_at is not None

    def mark_email_verified(self) -> None:
        """Mark user's email as verified."""
        self.is_email_verified = True
        self.email_verified_at = datetime.utcnow()

    def record_login(self) -> None:
        """Update last login timestamp."""
        self.last_login_at = datetime.utcnow()

    def soft_delete(self) -> None:
        """Soft delete the user account."""
        self.deleted_at = datetime.utcnow()
        self.is_active = False

    def restore(self) -> None:
        """Restore a soft-deleted user account."""
        self.deleted_at = None
        self.is_active = True

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"

    def __str__(self) -> str:
        return self.email