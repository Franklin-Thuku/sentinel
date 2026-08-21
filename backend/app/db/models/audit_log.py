"""
Audit Log model for Sentinel.

This model tracks all security-relevant actions for compliance,
forensics, and accountability purposes.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Text,
    Enum,
    Index,
    func,
    ForeignKey,
    JSON,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# ================================================================
# TYPE_CHECKING: Avoid circular import errors
# ================================================================

if TYPE_CHECKING:
    from app.db.models.user import User
    from app.db.models.organization import Organization


class AuditLog(Base):
    """
    Audit Log model.

    Tracks all security-relevant actions for compliance.

    Attributes:
        id: Unique UUID identifier
        user_id: ID of the user who performed the action
        organization_id: ID of the organization context
        action: Action performed (login, logout, scan_started, etc.)
        resource_type: Type of resource (user, website, scan, finding, etc.)
        resource_id: ID of the resource
        severity: Severity level (info, warning, error, critical)
        ip_address: IP address of the request
        user_agent: User agent of the request
        details: Additional details as JSON
        status: Action status (success, failure, pending)
        error_message: Error message if action failed
        created_at: Creation timestamp
    """

    __tablename__ = "audit_logs"

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

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ================================================================
    # Action Information
    # ================================================================

    action: Mapped[str] = mapped_column(
        Enum(
            # Authentication
            "user_login",
            "user_logout",
            "user_register",
            "user_password_reset",
            "user_email_verify",
            # User Management
            "user_create",
            "user_update",
            "user_delete",
            "user_role_change",
            # Website Management
            "website_add",
            "website_update",
            "website_delete",
            "website_verify",
            "website_verify_attempt",
            # Scan Management
            "scan_start",
            "scan_complete",
            "scan_fail",
            "scan_cancel",
            # Finding Management
            "finding_update",
            "finding_resolve",
            "finding_acknowledge",
            # Report Management
            "report_generate",
            "report_download",
            # Monitoring
            "monitoring_enable",
            "monitoring_disable",
            "monitoring_update",
            # Subscription
            "subscription_upgrade",
            "subscription_downgrade",
            "subscription_cancel",
            "subscription_reactivate",
            # Alert Management
            "alert_read",
            "alert_dismiss",
            # Organization
            "organization_create",
            "organization_update",
            "organization_delete",
            "organization_user_add",
            "organization_user_remove",
            # Admin
            "admin_user_suspend",
            "admin_user_unsuspend",
            "admin_system_config",
            # Security
            "security_alert_trigger",
            "security_threat_block",
            "login_failure",
            "api_key_create",
            "api_key_revoke",
            name="audit_action"
        ),
        nullable=False,
        index=True,
    )

    # ================================================================
    # Resource Information
    # ================================================================

    resource_type: Mapped[str] = mapped_column(
        Enum(
            "user",
            "organization",
            "website",
            "scan",
            "finding",
            "report",
            "alert",
            "subscription",
            "monitoring_config",
            "api_key",
            "system",
            "verification",
            name="audit_resource"
        ),
        nullable=False,
        index=True,
    )

    resource_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    # ================================================================
    # Severity
    # ================================================================

    severity: Mapped[str] = mapped_column(
        Enum(
            "info",
            "warning",
            "error",
            "critical",
            name="audit_severity"
        ),
        nullable=False,
        default="info",
        server_default="info",
        index=True,
    )

    # ================================================================
    # Request Context
    # ================================================================

    ip_address: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
        index=True,
    )

    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    # ================================================================
    # Details & Status
    # ================================================================

    details: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        Enum(
            "success",
            "failure",
            "pending",
            name="audit_status"
        ),
        nullable=False,
        default="success",
        server_default="success",
        index=True,
    )

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # ================================================================
    # Timestamp
    # ================================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    # ================================================================
    # Indexes
    # ================================================================

    __table_args__ = (
        Index("ix_audit_logs_user_id", "user_id"),
        Index("ix_audit_logs_organization_id", "organization_id"),
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_resource_type", "resource_type"),
        Index("ix_audit_logs_resource_id", "resource_id"),
        Index("ix_audit_logs_severity", "severity"),
        Index("ix_audit_logs_status", "status"),
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_ip_address", "ip_address"),
        Index("ix_audit_logs_user_action", "user_id", "action"),
        Index("ix_audit_logs_org_action", "organization_id", "action"),
        Index("ix_audit_logs_created_at_desc", "created_at"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="audit_logs",
        lazy="selectin",
    )

    organization: Mapped[Optional["Organization"]] = relationship(
        "Organization",
        back_populates="audit_logs",
        lazy="selectin",
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def action_display(self) -> str:
        """Get formatted action name."""
        return self.action.replace("_", " ").title()

    @property
    def resource_type_display(self) -> str:
        """Get formatted resource type name."""
        return self.resource_type.title()

    @property
    def severity_display(self) -> str:
        """Get formatted severity name."""
        return self.severity.upper()

    @property
    def status_display(self) -> str:
        """Get formatted status name."""
        return self.status.upper()

    @property
    def severity_color(self) -> str:
        """Get severity color for UI."""
        return {
            "info": "blue-400",
            "warning": "yellow-500",
            "error": "orange-500",
            "critical": "red-600",
        }.get(self.severity, "gray-400")

    @property
    def severity_icon(self) -> str:
        """Get severity icon for UI."""
        return {
            "info": "ℹ️",
            "warning": "⚠️",
            "error": "❌",
            "critical": "🔴",
        }.get(self.severity, "⚪")

    @property
    def time_ago(self) -> str:
        """Get human-readable time since log entry."""
        delta = datetime.utcnow() - self.created_at
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
            return self.created_at.strftime("%b %d, %Y")

    # ================================================================
    # Helper Methods
    # ================================================================

    def get_summary(self) -> dict:
        """
        Get a summary of the audit log entry.

        Returns:
            dict: Summary of the audit log entry.
        """
        return {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "action": self.action,
            "action_display": self.action_display,
            "resource_type": self.resource_type,
            "resource_type_display": self.resource_type_display,
            "resource_id": self.resource_id,
            "severity": self.severity,
            "severity_display": self.severity_display,
            "status": self.status,
            "status_display": self.status_display,
            "ip_address": self.ip_address,
            "error_message": self.error_message,
            "time_ago": self.time_ago,
            "created_at": self.created_at.isoformat(),
        }

    def get_details(self) -> dict:
        """
        Get the details of the audit log entry.

        Returns:
            dict: Details of the audit log entry.
        """
        return self.details or {}

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<AuditLog(id={self.id}, user_id={self.user_id}, "
            f"action={self.action}, resource_type={self.resource_type})>"
        )

    def __str__(self) -> str:
        return f"{self.action_display} on {self.resource_type_display} - {self.time_ago}"