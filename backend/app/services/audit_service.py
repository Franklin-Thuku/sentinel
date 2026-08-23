"""
Audit service for Sentinel.

Handles logging and retrieval of audit events for compliance,
forensics, and accountability purposes.
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from app.db.models.audit_log import AuditLog
from app.db.models.user import User
from app.db.models.organization import Organization


class AuditService:
    """
    Service for audit logging and management.

    Tracks all security-relevant actions for compliance and forensics.
    """

    def __init__(self, db: Session):
        """
        Initialize the audit service.

        Args:
            db: Database session
        """
        self.db = db

    # ================================================================
    # Audit Logging
    # ================================================================

    def log_event(
        self,
        user_id: Optional[UUID],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        organization_id: Optional[UUID] = None,
        severity: str = "info",
        status: str = "success",
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        """
        Log an audit event.

        Args:
            user_id: ID of the user (or None for system events)
            action: Action performed
            resource_type: Type of resource
            resource_id: ID of the resource
            organization_id: ID of the organization context
            severity: Severity level (info, warning, error, critical)
            status: Status (success, failure, pending)
            details: Additional details
            ip_address: IP address of the request
            user_agent: User agent of the request

        Returns:
            AuditLog: The created audit log
        """
        audit_log = AuditLog(
            id=uuid.uuid4(),
            user_id=user_id,
            organization_id=organization_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            severity=severity,
            status=status,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=datetime.utcnow(),
        )

        self.db.add(audit_log)
        self.db.commit()
        self.db.refresh(audit_log)

        return audit_log

    # ================================================================
    # Audit Retrieval
    # ================================================================

    def get_audit_logs(
        self,
        user_id: Optional[UUID] = None,
        organization_id: Optional[UUID] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Get audit logs with filters.

        Args:
            user_id: Filter by user ID
            organization_id: Filter by organization ID
            action: Filter by action
            resource_type: Filter by resource type
            severity: Filter by severity
            status: Filter by status
            start_date: Filter by start date
            end_date: Filter by end date
            skip: Number of records to skip
            limit: Maximum records to return

        Returns:
            List[AuditLog]: List of audit logs
        """
        query = self.db.query(AuditLog)

        if user_id:
            query = query.filter(AuditLog.user_id == user_id)

        if organization_id:
            query = query.filter(AuditLog.organization_id == organization_id)

        if action:
            query = query.filter(AuditLog.action == action)

        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)

        if severity:
            query = query.filter(AuditLog.severity == severity)

        if status:
            query = query.filter(AuditLog.status == status)

        if start_date:
            query = query.filter(AuditLog.created_at >= start_date)

        if end_date:
            query = query.filter(AuditLog.created_at <= end_date)

        return query.order_by(
            desc(AuditLog.created_at)
        ).offset(skip).limit(limit).all()

    def get_audit_log(self, log_id: UUID) -> Optional[AuditLog]:
        """
        Get a specific audit log by ID.

        Args:
            log_id: ID of the audit log

        Returns:
            Optional[AuditLog]: The audit log or None
        """
        return self.db.query(AuditLog).filter(
            AuditLog.id == log_id
        ).first()

    def get_user_audit_logs(
        self,
        user_id: UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> List[AuditLog]:
        """
        Get audit logs for a specific user.

        Args:
            user_id: ID of the user
            skip: Number of records to skip
            limit: Maximum records to return

        Returns:
            List[AuditLog]: List of audit logs
        """
        return self.db.query(AuditLog).filter(
            AuditLog.user_id == user_id
        ).order_by(
            desc(AuditLog.created_at)
        ).offset(skip).limit(limit).all()

    def get_organization_audit_logs(
        self,
        organization_id: UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> List[AuditLog]:
        """
        Get audit logs for a specific organization.

        Args:
            organization_id: ID of the organization
            skip: Number of records to skip
            limit: Maximum records to return

        Returns:
            List[AuditLog]: List of audit logs
        """
        return self.db.query(AuditLog).filter(
            AuditLog.organization_id == organization_id
        ).order_by(
            desc(AuditLog.created_at)
        ).offset(skip).limit(limit).all()

    def get_resource_audit_logs(
        self,
        resource_type: str,
        resource_id: str,
        skip: int = 0,
        limit: int = 50,
    ) -> List[AuditLog]:
        """
        Get audit logs for a specific resource.

        Args:
            resource_type: Type of resource
            resource_id: ID of the resource
            skip: Number of records to skip
            limit: Maximum records to return

        Returns:
            List[AuditLog]: List of audit logs
        """
        return self.db.query(AuditLog).filter(
            AuditLog.resource_type == resource_type,
            AuditLog.resource_id == resource_id
        ).order_by(
            desc(AuditLog.created_at)
        ).offset(skip).limit(limit).all()

    # ================================================================
    # Audit Statistics
    # ================================================================

    def get_audit_stats(
        self,
        organization_id: Optional[UUID] = None,
        days: int = 30,
    ) -> Dict[str, Any]:
        """
        Get audit statistics.

        Args:
            organization_id: Optional organization filter
            days: Number of days to analyze

        Returns:
            Dict[str, Any]: Audit statistics
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        query = self.db.query(AuditLog).filter(
            AuditLog.created_at >= start_date
        )

        if organization_id:
            query = query.filter(AuditLog.organization_id == organization_id)

        # Total count
        total = query.count()

        # Count by severity
        severity_counts = {}
        for severity in ["info", "warning", "error", "critical"]:
            count = query.filter(AuditLog.severity == severity).count()
            severity_counts[severity] = count

        # Count by status
        status_counts = {}
        for status in ["success", "failure", "pending"]:
            count = query.filter(AuditLog.status == status).count()
            status_counts[status] = count

        # Count by action
        action_counts = {}
        actions = [
            "user_login", "user_logout", "user_register",
            "website_add", "website_delete", "website_verify",
            "scan_start", "scan_complete", "scan_fail",
            "report_generate", "report_download",
            "subscription_upgrade", "subscription_cancel",
        ]
        for action in actions:
            count = query.filter(AuditLog.action == action).count()
            if count > 0:
                action_counts[action] = count

        # Get daily breakdown
        daily_counts = []
        for i in range(days, 0, -1):
            day = datetime.utcnow() - timedelta(days=i)
            day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day.replace(hour=23, minute=59, second=59, microsecond=999999)
            count = self.db.query(AuditLog).filter(
                AuditLog.created_at >= day_start,
                AuditLog.created_at <= day_end
            )
            if organization_id:
                count = count.filter(AuditLog.organization_id == organization_id)
            daily_counts.append({
                "date": day.strftime("%Y-%m-%d"),
                "count": count.count(),
            })

        return {
            "total_events": total,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "top_actions": sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            "daily_breakdown": daily_counts,
            "period_days": days,
        }

    def get_user_audit_stats(self, user_id: UUID, days: int = 30) -> Dict[str, Any]:
        """
        Get audit statistics for a specific user.

        Args:
            user_id: ID of the user
            days: Number of days to analyze

        Returns:
            Dict[str, Any]: User audit statistics
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        logs = self.db.query(AuditLog).filter(
            AuditLog.user_id == user_id,
            AuditLog.created_at >= start_date
        ).all()

        # Count by action
        action_counts = {}
        for log in logs:
            action_counts[log.action] = action_counts.get(log.action, 0) + 1

        return {
            "user_id": str(user_id),
            "total_events": len(logs),
            "action_counts": action_counts,
            "last_activity": logs[0].created_at.isoformat() if logs else None,
            "period_days": days,
        }

    # ================================================================
    # Audit Cleanup
    # ================================================================

    def cleanup_old_logs(self, retention_days: int = 90) -> int:
        """
        Delete audit logs older than retention period.

        Args:
            retention_days: Number of days to retain

        Returns:
            int: Number of logs deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

        deleted = self.db.query(AuditLog).filter(
            AuditLog.created_at < cutoff_date
        ).delete()

        self.db.commit()

        return deleted

    def export_audit_logs(
        self,
        organization_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Export audit logs for compliance.

        Args:
            organization_id: Optional organization filter
            start_date: Start date
            end_date: End date

        Returns:
            List[Dict[str, Any]]: List of audit logs as dictionaries
        """
        logs = self.get_audit_logs(
            organization_id=organization_id,
            start_date=start_date,
            end_date=end_date,
            limit=10000,  # Max export limit
        )

        return [
            {
                "id": str(log.id),
                "user_id": str(log.user_id) if log.user_id else None,
                "organization_id": str(log.organization_id) if log.organization_id else None,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "severity": log.severity,
                "status": log.status,
                "details": log.details,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ]

    # ================================================================
    # Audit Alerting
    # ================================================================

    def check_suspicious_activity(self, organization_id: UUID) -> List[Dict[str, Any]]:
        """
        Check for suspicious activity in audit logs.

        Args:
            organization_id: ID of the organization

        Returns:
            List[Dict[str, Any]]: List of suspicious activities
        """
        suspicious = []
        now = datetime.utcnow()

        # Check for multiple login failures
        failure_count = self.db.query(AuditLog).filter(
            AuditLog.organization_id == organization_id,
            AuditLog.action == "user_login",
            AuditLog.status == "failure",
            AuditLog.created_at >= now - timedelta(hours=1)
        ).count()

        if failure_count > 5:
            suspicious.append({
                "type": "multiple_login_failures",
                "severity": "warning",
                "description": f"Multiple login failures detected ({failure_count} in 1 hour)",
                "count": failure_count,
            })

        # Check for suspicious API calls
        suspicious_actions = self.db.query(AuditLog).filter(
            AuditLog.organization_id == organization_id,
            AuditLog.action.in_(["website_delete", "scan_cancel", "subscription_cancel"]),
            AuditLog.created_at >= now - timedelta(minutes=10)
        ).all()

        if suspicious_actions:
            suspicious.append({
                "type": "suspicious_actions",
                "severity": "warning",
                "description": f"Suspicious actions detected in last 10 minutes",
                "actions": [a.action for a in suspicious_actions],
            })

        return suspicious

    # ================================================================
    # User Activity Reports
    # ================================================================

    def get_user_activity_report(
        self,
        user_id: UUID,
        days: int = 7,
    ) -> Dict[str, Any]:
        """
        Generate a user activity report.

        Args:
            user_id: ID of the user
            days: Number of days to analyze

        Returns:
            Dict[str, Any]: User activity report
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        logs = self.db.query(AuditLog).filter(
            AuditLog.user_id == user_id,
            AuditLog.created_at >= start_date
        ).order_by(
            AuditLog.created_at.asc()
        ).all()

        # Group by date
        daily_activity = {}
        for log in logs:
            date_key = log.created_at.strftime("%Y-%m-%d")
            if date_key not in daily_activity:
                daily_activity[date_key] = {
                    "date": date_key,
                    "count": 0,
                    "actions": {},
                }
            daily_activity[date_key]["count"] += 1
            action = log.action
            if action not in daily_activity[date_key]["actions"]:
                daily_activity[date_key]["actions"][action] = 0
            daily_activity[date_key]["actions"][action] += 1

        # Get user info
        user = self.db.query(User).filter(
            User.id == user_id
        ).first()

        return {
            "user_id": str(user_id),
            "user_email": user.email if user else "Unknown",
            "period_days": days,
            "total_events": len(logs),
            "last_activity": logs[-1].created_at.isoformat() if logs else None,
            "daily_breakdown": list(daily_activity.values()),
            "top_actions": [
                {"action": k, "count": v}
                for k, v in self._count_actions(logs).items()
            ],
        }

    def _count_actions(self, logs: List[AuditLog]) -> Dict[str, int]:
        """Count actions in a list of logs."""
        counts = {}
        for log in logs:
            counts[log.action] = counts.get(log.action, 0) + 1
        return counts