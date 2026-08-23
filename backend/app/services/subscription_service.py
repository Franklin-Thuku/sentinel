"""
Subscription service for Sentinel.

Handles subscription plans, billing, and usage limits for organizations.
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models.subscription import Subscription
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.models.usage_record import UsageRecord
from app.db.models.audit_log import AuditLog


class SubscriptionService:
    """
    Service for subscription and billing management.
    """

    # Plan limits (copied from config for easy access)
    PLAN_LIMITS = {
        "free": {
            "websites": 1,
            "scans_per_month": 5,
            "ai_analysis_per_month": 5,
            "reports": False,
            "monitoring": False,
            "team_members": 1,
            "alerts": True,
        },
        "pro": {
            "websites": 25,
            "scans_per_month": 100,
            "ai_analysis_per_month": 100,
            "reports": True,
            "monitoring": True,
            "team_members": 5,
            "alerts": True,
        },
        "agency": {
            "websites": 500,
            "scans_per_month": 1000,
            "ai_analysis_per_month": 1000,
            "reports": True,
            "monitoring": True,
            "team_members": 50,
            "alerts": True,
        },
        "enterprise": {
            "websites": 9999,
            "scans_per_month": 9999,
            "ai_analysis_per_month": 9999,
            "reports": True,
            "monitoring": True,
            "team_members": 9999,
            "alerts": True,
        },
    }

    # Plan prices (in cents)
    PLAN_PRICES = {
        "free": 0,
        "pro": 4900,  # $49/month
        "agency": 29900,  # $299/month
        "enterprise": 99900,  # $999/month (custom)
    }

    def __init__(self, db: Session):
        """
        Initialize the subscription service.

        Args:
            db: Database session
        """
        self.db = db

    # ================================================================
    # Subscription Management
    # ================================================================

    def get_subscription(self, organization_id: UUID) -> Optional[Subscription]:
        """
        Get the subscription for an organization.

        Args:
            organization_id: ID of the organization

        Returns:
            Optional[Subscription]: The subscription or None
        """
        return self.db.query(Subscription).filter(
            Subscription.organization_id == organization_id
        ).first()

    def get_or_create_subscription(self, organization_id: UUID) -> Subscription:
        """
        Get or create a subscription for an organization.

        Args:
            organization_id: ID of the organization

        Returns:
            Subscription: The subscription
        """
        subscription = self.get_subscription(organization_id)

        if not subscription:
            subscription = Subscription(
                id=uuid.uuid4(),
                organization_id=organization_id,
                plan="free",
                status="active",
                provider="mock",
                current_period_start=datetime.utcnow(),
                current_period_end=datetime.utcnow() + timedelta(days=30),
                cancel_at_period_end=False,
            )
            self.db.add(subscription)
            self.db.commit()
            self.db.refresh(subscription)

        return subscription

    def update_subscription_plan(
        self,
        organization_id: UUID,
        plan: str,
        provider_subscription_id: Optional[str] = None,
        provider_customer_id: Optional[str] = None,
    ) -> Subscription:
        """
        Update an organization's subscription plan.

        Args:
            organization_id: ID of the organization
            plan: The new plan (free, pro, agency, enterprise)
            provider_subscription_id: ID from the payment provider
            provider_customer_id: Customer ID from the payment provider

        Returns:
            Subscription: The updated subscription

        Raises:
            HTTPException: If plan is invalid or organization not found
        """
        if plan not in self.PLAN_LIMITS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid plan: {plan}"
            )

        # Get organization
        organization = self.db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Get or create subscription
        subscription = self.get_or_create_subscription(organization_id)

        # Update plan
        subscription.plan = plan
        subscription.status = "active"
        subscription.current_period_start = datetime.utcnow()
        subscription.current_period_end = datetime.utcnow() + timedelta(days=30)
        subscription.cancel_at_period_end = False

        if provider_subscription_id:
            subscription.provider_subscription_id = provider_subscription_id

        if provider_customer_id:
            subscription.provider_customer_id = provider_customer_id

        self.db.commit()
        self.db.refresh(subscription)

        # Log the change
        self._log_audit_event(
            user_id=None,  # System action
            action="subscription_upgrade",
            resource_type="subscription",
            resource_id=str(subscription.id),
            details={
                "organization_id": str(organization_id),
                "plan": plan,
                "previous_plan": subscription.plan if subscription else None,
            },
        )

        return subscription

    def cancel_subscription(self, organization_id: UUID, at_period_end: bool = True) -> Subscription:
        """
        Cancel an organization's subscription.

        Args:
            organization_id: ID of the organization
            at_period_end: Whether to cancel at period end or immediately

        Returns:
            Subscription: The updated subscription

        Raises:
            HTTPException: If subscription not found
        """
        subscription = self.get_subscription(organization_id)

        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Subscription not found"
            )

        subscription.cancel(at_period_end)

        self.db.commit()
        self.db.refresh(subscription)

        # Log the cancellation
        self._log_audit_event(
            user_id=None,
            action="subscription_cancel",
            resource_type="subscription",
            resource_id=str(subscription.id),
            details={
                "organization_id": str(organization_id),
                "at_period_end": at_period_end,
            },
        )

        return subscription

    def reactivate_subscription(self, organization_id: UUID) -> Subscription:
        """
        Reactivate a canceled subscription.

        Args:
            organization_id: ID of the organization

        Returns:
            Subscription: The updated subscription

        Raises:
            HTTPException: If subscription not found
        """
        subscription = self.get_subscription(organization_id)

        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Subscription not found"
            )

        subscription.reactivate()

        self.db.commit()
        self.db.refresh(subscription)

        # Log the reactivation
        self._log_audit_event(
            user_id=None,
            action="subscription_reactivate",
            resource_type="subscription",
            resource_id=str(subscription.id),
            details={
                "organization_id": str(organization_id),
            },
        )

        return subscription

    # ================================================================
    # Usage Tracking
    # ================================================================

    def track_usage(
        self,
        organization_id: UUID,
        metric: str,
        count: int = 1,
        reference_id: Optional[str] = None,
    ) -> UsageRecord:
        """
        Track usage for an organization.

        Args:
            organization_id: ID of the organization
            metric: The usage metric (websites, scans, ai_analysis, reports)
            count: Number of units to add
            reference_id: External reference ID

        Returns:
            UsageRecord: The usage record

        Raises:
            HTTPException: If organization not found
        """
        # Get organization
        organization = self.db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Check if this usage was already tracked
        if reference_id:
            existing = self.db.query(UsageRecord).filter(
                UsageRecord.organization_id == organization_id,
                UsageRecord.metric == metric,
                UsageRecord.reference_id == reference_id,
            ).first()

            if existing:
                return existing

        # Create usage record
        usage = UsageRecord(
            id=uuid.uuid4(),
            organization_id=organization_id,
            metric=metric,
            count=count,
            period_start=datetime.utcnow().replace(day=1, hour=0, minute=0, second=0),
            period_end=(datetime.utcnow().replace(day=1, hour=0, minute=0, second=0) + timedelta(days=32)).replace(day=1),
            reference_id=reference_id,
        )

        self.db.add(usage)
        self.db.commit()
        self.db.refresh(usage)

        return usage

    def get_usage(
        self,
        organization_id: UUID,
        metric: Optional[str] = None,
        period_start: Optional[datetime] = None,
        period_end: Optional[datetime] = None,
    ) -> List[UsageRecord]:
        """
        Get usage records for an organization.

        Args:
            organization_id: ID of the organization
            metric: Optional filter by metric
            period_start: Start of period
            period_end: End of period

        Returns:
            List[UsageRecord]: List of usage records
        """
        query = self.db.query(UsageRecord).filter(
            UsageRecord.organization_id == organization_id
        )

        if metric:
            query = query.filter(UsageRecord.metric == metric)

        if period_start:
            query = query.filter(UsageRecord.period_start >= period_start)

        if period_end:
            query = query.filter(UsageRecord.period_end <= period_end)

        return query.order_by(
            UsageRecord.created_at.desc()
        ).all()

    def get_current_usage(self, organization_id: UUID) -> Dict[str, int]:
        """
        Get current usage for an organization for the current period.

        Args:
            organization_id: ID of the organization

        Returns:
            Dict[str, int]: Current usage counts
        """
        # Get start of current period
        period_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0)

        usage = self.db.query(UsageRecord).filter(
            UsageRecord.organization_id == organization_id,
            UsageRecord.period_start >= period_start
        ).all()

        # Aggregate by metric
        result = {}
        for record in usage:
            if record.metric not in result:
                result[record.metric] = 0
            result[record.metric] += record.count

        return result

    def check_usage_limit(
        self,
        organization_id: UUID,
        metric: str,
        additional: int = 1,
    ) -> bool:
        """
        Check if usage would exceed the plan limit.

        Args:
            organization_id: ID of the organization
            metric: The usage metric
            additional: Additional units to check

        Returns:
            bool: True if under limit, False if would exceed
        """
        # Get subscription
        subscription = self.get_subscription(organization_id)

        if not subscription:
            return True  # Allow if no subscription (shouldn't happen)

        # Get plan limits
        plan_limits = self.PLAN_LIMITS.get(subscription.plan, self.PLAN_LIMITS["free"])
        limit = plan_limits.get(metric, 0)

        if limit == 0:
            return False  # Not allowed

        # Get current usage
        current_usage = self.get_current_usage(organization_id)
        current = current_usage.get(metric, 0)

        return (current + additional) <= limit

    def enforce_usage_limit(
        self,
        organization_id: UUID,
        metric: str,
        additional: int = 1,
    ) -> None:
        """
        Enforce usage limits, raise exception if exceeded.

        Args:
            organization_id: ID of the organization
            metric: The usage metric
            additional: Additional units to check

        Raises:
            HTTPException: If usage limit would be exceeded
        """
        if not self.check_usage_limit(organization_id, metric, additional):
            subscription = self.get_subscription(organization_id)
            plan = subscription.plan if subscription else "free"
            current = self.get_current_usage(organization_id).get(metric, 0)
            limit = self.PLAN_LIMITS.get(plan, self.PLAN_LIMITS["free"]).get(metric, 0)

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Usage limit exceeded for {metric}. "
                    f"Current: {current}, Limit: {limit}, Plan: {plan}"
                )
            )

    # ================================================================
    # Plan Information
    # ================================================================

    def get_plan_limits(self, plan: str) -> Dict[str, Any]:
        """
        Get limits for a plan.

        Args:
            plan: The plan name

        Returns:
            Dict[str, Any]: Plan limits
        """
        return self.PLAN_LIMITS.get(plan, self.PLAN_LIMITS["free"])

    def get_plan_price(self, plan: str) -> int:
        """
        Get price for a plan in cents.

        Args:
            plan: The plan name

        Returns:
            int: Price in cents
        """
        return self.PLAN_PRICES.get(plan, 0)

    def get_all_plans(self) -> List[Dict[str, Any]]:
        """
        Get all available plans.

        Returns:
            List[Dict[str, Any]]: List of plans
        """
        plans = []
        for plan_name, limits in self.PLAN_LIMITS.items():
            plans.append({
                "name": plan_name,
                "display_name": plan_name.capitalize(),
                "price": self.PLAN_PRICES.get(plan_name, 0),
                "price_display": f"${self.PLAN_PRICES.get(plan_name, 0) / 100:.2f}",
                "limits": limits,
            })
        return plans

    def get_organization_plan_info(self, organization_id: UUID) -> Dict[str, Any]:
        """
        Get plan information for an organization.

        Args:
            organization_id: ID of the organization

        Returns:
            Dict[str, Any]: Plan information
        """
        subscription = self.get_subscription(organization_id)

        if not subscription:
            return {
                "plan": "free",
                "status": "active",
                "limits": self.PLAN_LIMITS["free"],
                "usage": {},
            }

        current_usage = self.get_current_usage(organization_id)

        return {
            "plan": subscription.plan,
            "status": subscription.status,
            "limits": self.PLAN_LIMITS.get(subscription.plan, self.PLAN_LIMITS["free"]),
            "usage": current_usage,
            "current_period_end": subscription.current_period_end.isoformat(),
            "cancel_at_period_end": subscription.cancel_at_period_end,
            "days_until_renewal": subscription.days_until_renewal,
        }

    # ================================================================
    # Webhook Handling
    # ================================================================

    def handle_payment_webhook(self, webhook_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle payment provider webhook events.

        Args:
            webhook_data: Webhook payload

        Returns:
            Dict[str, Any]: Response
        """
        event_type = webhook_data.get("type")
        event_data = webhook_data.get("data", {})

        if event_type == "subscription_created":
            return self._handle_subscription_created(event_data)
        elif event_type == "subscription_updated":
            return self._handle_subscription_updated(event_data)
        elif event_type == "subscription_deleted":
            return self._handle_subscription_deleted(event_data)
        elif event_type == "invoice_paid":
            return self._handle_invoice_paid(event_data)
        elif event_type == "invoice_failed":
            return self._handle_invoice_failed(event_data)

        return {"status": "ignored", "event_type": event_type}

    def _handle_subscription_created(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription created webhook."""
        # This would be implemented with actual payment provider integration
        return {"status": "processed", "action": "subscription_created"}

    def _handle_subscription_updated(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription updated webhook."""
        return {"status": "processed", "action": "subscription_updated"}

    def _handle_subscription_deleted(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription deleted webhook."""
        return {"status": "processed", "action": "subscription_deleted"}

    def _handle_invoice_paid(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice paid webhook."""
        return {"status": "processed", "action": "invoice_paid"}

    def _handle_invoice_failed(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice failed webhook."""
        return {"status": "processed", "action": "invoice_failed"}

    # ================================================================
    # Helper Methods
    # ================================================================

    def _log_audit_event(
        self,
        user_id: Optional[UUID],
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[dict] = None,
    ) -> None:
        """
        Log an audit event.

        Args:
            user_id: ID of the user (or None for system)
            action: Action performed
            resource_type: Type of resource
            resource_id: ID of the resource
            details: Additional details
        """
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            severity="info",
            status="success",
        )

        self.db.add(audit_log)
        self.db.commit()