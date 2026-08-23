"""
Alert service for Sentinel.

Handles security alerts for users based on findings, score changes,
and system events.
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from app.db.models.alert import Alert
from app.db.models.finding import Finding
from app.db.models.scan import Scan
from app.db.models.website import Website
from app.db.models.user import User
from app.db.models.security_score import SecurityScore
from app.db.models.audit_log import AuditLog


class AlertService:
    """
    Service for alert management.

    Creates, retrieves, and manages security alerts for users.
    """

    def __init__(self, db: Session):
        """
        Initialize the alert service.

        Args:
            db: Database session
        """
        self.db = db

    # ================================================================
    # Alert Creation
    # ================================================================

    def create_alert(
        self,
        user_id: UUID,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        website_id: Optional[UUID] = None,
        scan_id: Optional[UUID] = None,
        details: Optional[Dict[str, Any]] = None,
        action_url: Optional[str] = None,
        action_label: Optional[str] = None,
    ) -> Alert:
        """
        Create a new alert for a user.

        Args:
            user_id: ID of the user
            alert_type: Type of alert
            severity: Severity level
            title: Alert title
            description: Alert description
            website_id: Optional website ID
            scan_id: Optional scan ID
            details: Additional details
            action_url: URL for action
            action_label: Label for action button

        Returns:
            Alert: The created alert
        """
        alert = Alert(
            id=uuid.uuid4(),
            user_id=user_id,
            website_id=website_id,
            scan_id=scan_id,
            type=alert_type,
            severity=severity,
            title=title,
            description=description,
            details=details or {},
            action_url=action_url,
            action_label=action_label,
            is_read=False,
            is_dismissed=False,
            triggered_at=datetime.utcnow(),
        )

        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)

        return alert

    # ================================================================
    # Alert Triggers
    # ================================================================

    def trigger_critical_finding_alert(self, finding: Finding) -> Optional[Alert]:
        """
        Trigger an alert for a critical finding.

        Args:
            finding: The finding

        Returns:
            Optional[Alert]: The created alert or None
        """
        # Only trigger for critical findings
        if finding.severity not in ("critical", "high"):
            return None

        # Check if alert already exists for this finding
        existing = self.db.query(Alert).filter(
            Alert.scan_id == finding.scan_id,
            Alert.type.in_(["finding_critical", "finding_high"]),
            Alert.details["finding_id"].astext == str(finding.id),
        ).first()

        if existing:
            return existing

        severity_map = {
            "critical": ("finding_critical", "Critical"),
            "high": ("finding_high", "High"),
        }

        alert_type, severity_label = severity_map.get(
            finding.severity,
            ("finding_new", "New")
        )

        # Get website and user
        website = self.db.query(Website).filter(
            Website.id == finding.website_id
        ).first()

        if not website:
            return None

        # Get user
        user = self.db.query(User).filter(
            User.id == website.user_id
        ).first()

        if not user:
            return None

        # Create alert
        return self.create_alert(
            user_id=user.id,
            alert_type=alert_type,
            severity=finding.severity,
            title=f"{severity_label} Severity Finding: {finding.title}",
            description=f"On {website.domain}: {finding.description[:200]}...",
            website_id=website.id,
            scan_id=finding.scan_id,
            details={"finding_id": str(finding.id)},
            action_url=f"/scans/{finding.scan_id}/findings/{finding.id}",
            action_label="View Finding",
        )

    def trigger_score_drop_alert(
        self,
        scan: Scan,
        previous_score: int,
        new_score: int,
        threshold: int = 10,
    ) -> Optional[Alert]:
        """
        Trigger an alert for a significant score drop.

        Args:
            scan: The scan
            previous_score: Previous score
            new_score: New score
            threshold: Minimum drop to trigger alert

        Returns:
            Optional[Alert]: The created alert or None
        """
        drop = previous_score - new_score

        if drop < threshold:
            return None

        # Get website
        website = self.db.query(Website).filter(
            Website.id == scan.website_id
        ).first()

        if not website:
            return None

        # Get user
        user = self.db.query(User).filter(
            User.id == website.user_id
        ).first()

        if not user:
            return None

        # Check if alert already exists for this scan
        existing = self.db.query(Alert).filter(
            Alert.scan_id == scan.id,
            Alert.type == "score_drop"
        ).first()

        if existing:
            return existing

        return self.create_alert(
            user_id=user.id,
            alert_type="score_drop",
            severity="high" if drop > 20 else "medium",
            title=f"Security Score Dropped by {drop} Points",
            description=f"On {website.domain}: Score dropped from {previous_score} to {new_score}",
            website_id=website.id,
            scan_id=scan.id,
            details={
                "previous_score": previous_score,
                "new_score": new_score,
                "drop": drop,
            },
            action_url=f"/scans/{scan.id}",
            action_label="View Scan",
        )

    def trigger_scan_failed_alert(self, scan: Scan) -> Optional[Alert]:
        """
        Trigger an alert for a failed scan.

        Args:
            scan: The failed scan

        Returns:
            Optional[Alert]: The created alert or None
        """
        # Get website
        website = self.db.query(Website).filter(
            Website.id == scan.website_id
        ).first()

        if not website:
            return None

        # Get user
        user = self.db.query(User).filter(
            User.id == website.user_id
        ).first()

        if not user:
            return None

        # Check if alert already exists for this scan
        existing = self.db.query(Alert).filter(
            Alert.scan_id == scan.id,
            Alert.type == "scan_failed"
        ).first()

        if existing:
            return existing

        return self.create_alert(
            user_id=user.id,
            alert_type="scan_failed",
            severity="high",
            title="Scan Failed",
            description=f"Scan on {website.domain} failed: {scan.error_message or 'Unknown error'}",
            website_id=website.id,
            scan_id=scan.id,
            details={"error_message": scan.error_message},
            action_url=f"/scans/{scan.id}",
            action_label="View Scan",
        )

    def trigger_monitoring_disabled_alert(self, website: Website) -> Optional[Alert]:
        """
        Trigger an alert when monitoring is disabled.

        Args:
            website: The website

        Returns:
            Optional[Alert]: The created alert or None
        """
        # Get user
        user = self.db.query(User).filter(
            User.id == website.user_id
        ).first()

        if not user:
            return None

        return self.create_alert(
            user_id=user.id,
            alert_type="monitoring_disabled",
            severity="medium",
            title="Monitoring Disabled",
            description=f"Monitoring on {website.domain} has been disabled",
            website_id=website.id,
            details={"reason": "Monitoring limit reached or manual disable"},
            action_url=f"/websites/{website.id}",
            action_label="Re-enable Monitoring",
        )

    # ================================================================
    # Alert Retrieval
    # ================================================================

    def get_alerts(
        self,
        user_id: UUID,
        is_read: Optional[bool] = None,
        is_dismissed: Optional[bool] = None,
        severity: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[Alert]:
        """
        Get alerts for a user.

        Args:
            user_id: ID of the user
            is_read: Filter by read status
            is_dismissed: Filter by dismissed status
            severity: Filter by severity
            skip: Number of records to skip
            limit: Maximum records to return

        Returns:
            List[Alert]: List of alerts
        """
        query = self.db.query(Alert).filter(
            Alert.user_id == user_id
        )

        if is_read is not None:
            query = query.filter(Alert.is_read == is_read)

        if is_dismissed is not None:
            query = query.filter(Alert.is_dismissed == is_dismissed)

        if severity:
            query = query.filter(Alert.severity == severity)

        return query.order_by(
            Alert.triggered_at.desc()
        ).offset(skip).limit(limit).all()

    def get_unread_count(self, user_id: UUID) -> int:
        """
        Get count of unread alerts for a user.

        Args:
            user_id: ID of the user

        Returns:
            int: Number of unread alerts
        """
        return self.db.query(Alert).filter(
            Alert.user_id == user_id,
            Alert.is_read == False,
            Alert.is_dismissed == False
        ).count()

    def get_active_alerts(self, user_id: UUID) -> List[Alert]:
        """
        Get active (unread and not dismissed) alerts for a user.

        Args:
            user_id: ID of the user

        Returns:
            List[Alert]: List of active alerts
        """
        return self.db.query(Alert).filter(
            Alert.user_id == user_id,
            Alert.is_read == False,
            Alert.is_dismissed == False
        ).order_by(
            Alert.triggered_at.desc()
        ).all()

    def get_alert_by_id(self, alert_id: UUID, user_id: UUID) -> Alert:
        """
        Get a specific alert by ID.

        Args:
            alert_id: ID of the alert
            user_id: ID of the user (for authorization)

        Returns:
            Alert: The alert

        Raises:
            HTTPException: If alert not found
        """
        alert = self.db.query(Alert).filter(
            Alert.id == alert_id,
            Alert.user_id == user_id
        ).first()

        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )

        return alert

    def get_alerts_for_website(
        self,
        website_id: UUID,
        user_id: UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> List[Alert]:
        """
        Get alerts for a specific website.

        Args:
            website_id: ID of the website
            user_id: ID of the user (for authorization)
            skip: Number of records to skip
            limit: Maximum records to return

        Returns:
            List[Alert]: List of alerts
        """
        return self.db.query(Alert).filter(
            Alert.website_id == website_id,
            Alert.user_id == user_id
        ).order_by(
            Alert.triggered_at.desc()
        ).offset(skip).limit(limit).all()

    # ================================================================
    # Alert Management
    # ================================================================

    def mark_read(self, alert_id: UUID, user_id: UUID) -> Alert:
        """
        Mark an alert as read.

        Args:
            alert_id: ID of the alert
            user_id: ID of the user

        Returns:
            Alert: The updated alert

        Raises:
            HTTPException: If alert not found
        """
        alert = self.get_alert_by_id(alert_id, user_id)
        alert.mark_read()
        self.db.commit()
        self.db.refresh(alert)

        # Log the action
        self._log_audit_event(
            user_id=user_id,
            action="alert_read",
            resource_type="alert",
            resource_id=str(alert_id),
            details={"alert_type": alert.type},
        )

        return alert

    def mark_unread(self, alert_id: UUID, user_id: UUID) -> Alert:
        """
        Mark an alert as unread.

        Args:
            alert_id: ID of the alert
            user_id: ID of the user

        Returns:
            Alert: The updated alert

        Raises:
            HTTPException: If alert not found
        """
        alert = self.get_alert_by_id(alert_id, user_id)
        alert.mark_unread()
        self.db.commit()
        self.db.refresh(alert)

        return alert

    def dismiss_alert(self, alert_id: UUID, user_id: UUID) -> Alert:
        """
        Dismiss an alert.

        Args:
            alert_id: ID of the alert
            user_id: ID of the user

        Returns:
            Alert: The updated alert

        Raises:
            HTTPException: If alert not found
        """
        alert = self.get_alert_by_id(alert_id, user_id)
        alert.dismiss()
        self.db.commit()
        self.db.refresh(alert)

        # Log the action
        self._log_audit_event(
            user_id=user_id,
            action="alert_dismiss",
            resource_type="alert",
            resource_id=str(alert_id),
            details={"alert_type": alert.type},
        )

        return alert

    def restore_alert(self, alert_id: UUID, user_id: UUID) -> Alert:
        """
        Restore a dismissed alert.

        Args:
            alert_id: ID of the alert
            user_id: ID of the user

        Returns:
            Alert: The updated alert

        Raises:
            HTTPException: If alert not found
        """
        alert = self.get_alert_by_id(alert_id, user_id)
        alert.restore()
        self.db.commit()
        self.db.refresh(alert)

        return alert

    def mark_all_read(self, user_id: UUID) -> int:
        """
        Mark all alerts as read for a user.

        Args:
            user_id: ID of the user

        Returns:
            int: Number of alerts marked as read
        """
        alerts = self.db.query(Alert).filter(
            Alert.user_id == user_id,
            Alert.is_read == False
        ).all()

        count = len(alerts)
        for alert in alerts:
            alert.mark_read()

        self.db.commit()
        return count

    def dismiss_all(self, user_id: UUID) -> int:
        """
        Dismiss all alerts for a user.

        Args:
            user_id: ID of the user

        Returns:
            int: Number of alerts dismissed
        """
        alerts = self.db.query(Alert).filter(
            Alert.user_id == user_id,
            Alert.is_dismissed == False
        ).all()

        count = len(alerts)
        for alert in alerts:
            alert.dismiss()

        self.db.commit()
        return count

    def delete_alert(self, alert_id: UUID, user_id: UUID) -> None:
        """
        Delete an alert permanently.

        Args:
            alert_id: ID of the alert
            user_id: ID of the user

        Raises:
            HTTPException: If alert not found
        """
        alert = self.get_alert_by_id(alert_id, user_id)
        self.db.delete(alert)
        self.db.commit()

    # ================================================================
    # Alert Statistics
    # ================================================================

    def get_alert_stats(self, user_id: UUID) -> Dict[str, Any]:
        """
        Get alert statistics for a user.

        Args:
            user_id: ID of the user

        Returns:
            Dict[str, Any]: Alert statistics
        """
        total = self.db.query(Alert).filter(
            Alert.user_id == user_id
        ).count()

        unread = self.db.query(Alert).filter(
            Alert.user_id == user_id,
            Alert.is_read == False,
            Alert.is_dismissed == False
        ).count()

        # Count by severity
        severity_counts = {}
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = self.db.query(Alert).filter(
                Alert.user_id == user_id,
                Alert.severity == severity
            ).count()
            severity_counts[severity] = count

        # Count by type
        type_counts = {}
        types = [
            "finding_critical", "finding_high", "finding_new",
            "score_change", "score_drop", "scan_failed",
            "scan_completed", "verification_required",
            "verification_expired", "monitoring_disabled",
        ]
        for alert_type in types:
            count = self.db.query(Alert).filter(
                Alert.user_id == user_id,
                Alert.type == alert_type
            ).count()
            type_counts[alert_type] = count

        # Get recent alerts
        recent = self.db.query(Alert).filter(
            Alert.user_id == user_id
        ).order_by(
            Alert.triggered_at.desc()
        ).limit(5).all()

        return {
            "total": total,
            "unread": unread,
            "severity_counts": severity_counts,
            "type_counts": type_counts,
            "recent": [
                {
                    "id": str(a.id),
                    "type": a.type,
                    "severity": a.severity,
                    "title": a.title,
                    "time_ago": a.time_ago,
                    "is_read": a.is_read,
                }
                for a in recent
            ],
        }

    # ================================================================
    # Helper Methods
    # ================================================================

    def _log_audit_event(
        self,
        user_id: UUID,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[dict] = None,
    ) -> None:
        """
        Log an audit event.

        Args:
            user_id: ID of the user
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