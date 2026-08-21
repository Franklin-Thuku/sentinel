"""
Subscription model for Sentinel.

This model manages organization subscription plans and billing.
It tracks plan type, status, payment provider integration, and billing periods.
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Boolean,
    Enum,
    Index,
    func,
    ForeignKey,
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
    from app.db.models.organization import Organization


class Subscription(Base):
    """
    Subscription model.

    Manages organization subscription plans and billing.

    Attributes:
        id: Unique UUID identifier
        organization_id: ID of the organization
        plan: Subscription plan (free, pro, agency, enterprise)
        status: Subscription status (active, past_due, canceled, expired, trialing)
        provider: Payment provider (stripe, paddle, mock)
        provider_subscription_id: ID from the payment provider
        provider_customer_id: Customer ID from the payment provider
        provider_price_id: Price ID from the payment provider
        quantity: Number of units (if applicable)
        current_period_start: Start of current billing period
        current_period_end: End of current billing period
        cancel_at_period_end: Whether to cancel at period end
        canceled_at: When the subscription was canceled
        trial_start: Start of trial period
        trial_end: End of trial period
        billing_email: Email address for billing
        billing_address: Billing address (JSON)
        tax_id: Tax/VAT ID
        metadata: Additional metadata as JSON
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "subscriptions"

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
        unique=True,  # One subscription per organization
        index=True,
    )

    # ================================================================
    # Plan Information
    # ================================================================

    plan: Mapped[str] = mapped_column(
        Enum(
            "free",
            "pro",
            "agency",
            "enterprise",
            name="subscription_plan"
        ),
        nullable=False,
        default="free",
        server_default="free",
        index=True,
    )

    status: Mapped[str] = mapped_column(
        Enum(
            "active",
            "past_due",
            "canceled",
            "expired",
            "trialing",
            "incomplete",
            "incomplete_expired",
            name="subscription_status"
        ),
        nullable=False,
        default="active",
        server_default="active",
        index=True,
    )

    # ================================================================
    # Payment Provider Integration
    # ================================================================

    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="stripe",
        server_default="stripe",
    )

    provider_subscription_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    provider_customer_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    provider_price_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    quantity: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
    )

    # ================================================================
    # Billing Periods
    # ================================================================

    current_period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    current_period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    cancel_at_period_end: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    canceled_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ================================================================
    # Trial
    # ================================================================

    trial_start: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    trial_end: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ================================================================
    # Billing Information
    # ================================================================

    billing_email: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    billing_address: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    tax_id: Mapped[Optional[str]] = mapped_column(
        String(50),
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

    # ================================================================
    # Indexes
    # ================================================================

    __table_args__ = (
        Index("ix_subscriptions_organization_id", "organization_id"),
        Index("ix_subscriptions_plan", "plan"),
        Index("ix_subscriptions_status", "status"),
        Index("ix_subscriptions_provider_subscription_id", "provider_subscription_id"),
        Index("ix_subscriptions_provider_customer_id", "provider_customer_id"),
        Index("ix_subscriptions_current_period_end", "current_period_end"),
        Index("ix_subscriptions_plan_status", "plan", "status"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="subscriptions",
        lazy="selectin",
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def is_active(self) -> bool:
        """Check if subscription is active."""
        return self.status in ("active", "trialing")

    @property
    def is_free(self) -> bool:
        """Check if subscription is free."""
        return self.plan == "free"

    @property
    def is_pro(self) -> bool:
        """Check if subscription is pro."""
        return self.plan == "pro"

    @property
    def is_agency(self) -> bool:
        """Check if subscription is agency."""
        return self.plan == "agency"

    @property
    def is_enterprise(self) -> bool:
        """Check if subscription is enterprise."""
        return self.plan == "enterprise"

    @property
    def is_past_due(self) -> bool:
        """Check if subscription is past due."""
        return self.status == "past_due"

    @property
    def is_canceled(self) -> bool:
        """Check if subscription is canceled."""
        return self.status == "canceled"

    @property
    def is_expired(self) -> bool:
        """Check if subscription is expired."""
        return self.status == "expired"

    @property
    def is_trialing(self) -> bool:
        """Check if subscription is in trial."""
        return self.status == "trialing"

    @property
    def is_on_trial(self) -> bool:
        """Check if subscription is currently in trial period."""
        if not self.trial_start or not self.trial_end:
            return False
        now = datetime.utcnow()
        return self.trial_start <= now <= self.trial_end

    @property
    def days_until_renewal(self) -> Optional[int]:
        """Get days until renewal."""
        if self.current_period_end:
            now = datetime.utcnow()
            if now < self.current_period_end:
                return (self.current_period_end - now).days
        return None

    @property
    def plan_display(self) -> str:
        """Get formatted plan name."""
        return {
            "free": "Free",
            "pro": "Pro",
            "agency": "Agency",
            "enterprise": "Enterprise",
        }.get(self.plan, "Unknown")

    @property
    def status_display(self) -> str:
        """Get formatted status name."""
        return {
            "active": "Active",
            "past_due": "Past Due",
            "canceled": "Canceled",
            "expired": "Expired",
            "trialing": "Trial",
            "incomplete": "Incomplete",
            "incomplete_expired": "Incomplete (Expired)",
        }.get(self.status, "Unknown")

    # ================================================================
    # Helper Methods
    # ================================================================

    def cancel(self, at_period_end: bool = True) -> None:
        """Cancel the subscription."""
        if at_period_end:
            self.cancel_at_period_end = True
        else:
            self.status = "canceled"
            self.canceled_at = datetime.utcnow()

    def reactivate(self) -> None:
        """Reactivate a canceled subscription."""
        self.cancel_at_period_end = False
        self.status = "active"
        self.canceled_at = None

    def mark_past_due(self) -> None:
        """Mark subscription as past due."""
        self.status = "past_due"

    def mark_active(self) -> None:
        """Mark subscription as active."""
        self.status = "active"

    def mark_expired(self) -> None:
        """Mark subscription as expired."""
        self.status = "expired"

    def mark_trialing(self) -> None:
        """Mark subscription as trialing."""
        self.status = "trialing"

    def set_period(self, start: datetime, end: datetime) -> None:
        """Set the current billing period."""
        self.current_period_start = start
        self.current_period_end = end

    def set_trial(self, start: datetime, end: datetime) -> None:
        """Set the trial period."""
        self.trial_start = start
        self.trial_end = end
        self.status = "trialing"

    def extend_trial(self, days: int) -> None:
        """Extend the trial period."""
        if self.trial_end:
            self.trial_end = self.trial_end + timedelta(days=days)
        else:
            self.trial_start = datetime.utcnow()
            self.trial_end = datetime.utcnow() + timedelta(days=days)
        self.status = "trialing"

    def get_plan_limits(self) -> dict:
        """
        Get limits for the current plan.

        Returns:
            dict: Plan limits.
        """
        limits = {
            "free": {
                "websites": 1,
                "scans_per_month": 5,
                "ai_analysis_per_month": 5,
                "monitoring": False,
                "reports": False,
                "team_members": 1,
            },
            "pro": {
                "websites": 25,
                "scans_per_month": 100,
                "ai_analysis_per_month": 100,
                "monitoring": True,
                "reports": True,
                "team_members": 5,
            },
            "agency": {
                "websites": 500,
                "scans_per_month": 1000,
                "ai_analysis_per_month": 1000,
                "monitoring": True,
                "reports": True,
                "team_members": 50,
            },
            "enterprise": {
                "websites": 9999,
                "scans_per_month": 9999,
                "ai_analysis_per_month": 9999,
                "monitoring": True,
                "reports": True,
                "team_members": 9999,
            },
        }
        return limits.get(self.plan, limits["free"])

    def get_summary(self) -> dict:
        """
        Get a summary of the subscription.

        Returns:
            dict: Summary of the subscription.
        """
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "plan": self.plan,
            "plan_display": self.plan_display,
            "status": self.status,
            "status_display": self.status_display,
            "is_active": self.is_active,
            "is_on_trial": self.is_on_trial,
            "current_period_start": self.current_period_start.isoformat(),
            "current_period_end": self.current_period_end.isoformat(),
            "days_until_renewal": self.days_until_renewal,
            "cancel_at_period_end": self.cancel_at_period_end,
            "provider": self.provider,
            "billing_email": self.billing_email,
            "limits": self.get_plan_limits(),
        }

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<Subscription(id={self.id}, organization_id={self.organization_id}, "
            f"plan={self.plan}, status={self.status})>"
        )

    def __str__(self) -> str:
        return f"{self.plan_display} subscription for org {self.organization_id} - {self.status_display}"