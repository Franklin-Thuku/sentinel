"""
Monitoring service for Sentinel.

Handles scheduled scans and continuous monitoring of websites.
"""

import uuid
from datetime import datetime, timedelta, time
from typing import List, Optional, Dict, Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from app.db.models.monitoring_config import MonitoringConfig
from app.db.models.website import Website
from app.db.models.user import User
from app.db.models.scan import Scan
from app.db.models.audit_log import AuditLog
from app.services.scan_service import ScanService
from app.services.alert_service import AlertService


class MonitoringService:
    """
    Service for monitoring configuration and execution.
    """

    def __init__(self, db: Session):
        """
        Initialize the monitoring service.

        Args:
            db: Database session
        """
        self.db = db
        self.scan_service = ScanService(db)
        self.alert_service = AlertService(db)

    # ================================================================
    # Monitoring Configuration
    # ================================================================

    def create_monitoring_config(
        self,
        website_id: UUID,
        user_id: UUID,
        frequency: str = "weekly",
        scan_type: str = "full",
        time_of_day: Optional[str] = None,
        day_of_week: Optional[int] = None,
        day_of_month: Optional[int] = None,
        notification_channels: Optional[List[str]] = None,
    ) -> MonitoringConfig:
        """
        Create a monitoring configuration for a website.

        Args:
            website_id: ID of the website
            user_id: ID of the user
            frequency: daily, weekly, monthly, custom
            scan_type: full, quick, passive
            time_of_day: Time of day in format "HH:MM"
            day_of_week: Day of week (0=Monday, 6=Sunday)
            day_of_month: Day of month (1-31)
            notification_channels: List of notification channels

        Returns:
            MonitoringConfig: The created monitoring config

        Raises:
            HTTPException: If website not found or config already exists
        """
        # Get website
        website = self.db.query(Website).filter(
            Website.id == website_id,
            Website.user_id == user_id,
            Website.deleted_at.is_(None)
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Website not found"
            )

        if not website.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Website must be verified before monitoring"
            )

        # Check if config already exists
        existing = self.db.query(MonitoringConfig).filter(
            MonitoringConfig.website_id == website_id,
            MonitoringConfig.is_active == True
        ).first()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Monitoring already configured for this website"
            )

        # Parse time_of_day
        parsed_time = None
        if time_of_day:
            try:
                hours, minutes = map(int, time_of_day.split(":"))
                parsed_time = time(hours, minutes)
            except (ValueError, TypeError):
                pass

        # Create config
        config = MonitoringConfig(
            id=uuid.uuid4(),
            website_id=website_id,
            user_id=user_id,
            frequency=frequency,
            scan_type=scan_type,
            time_of_day=parsed_time or time(0, 0),
            day_of_week=day_of_week,
            day_of_month=day_of_month,
            is_active=True,
            notification_channels=notification_channels or ["email"],
            max_failures=3,
            failure_count=0,
        )

        # Calculate next run
        config.next_run_at = self._calculate_next_run(config)

        self.db.add(config)
        self.db.commit()
        self.db.refresh(config)

        # Log the creation
        self._log_audit_event(
            user_id=user_id,
            action="monitoring_enable",
            resource_type="monitoring_config",
            resource_id=str(config.id),
            details={
                "website_id": str(website_id),
                "frequency": frequency,
                "scan_type": scan_type,
            },
        )

        return config

    def get_monitoring_config(self, config_id: UUID, user_id: UUID) -> MonitoringConfig:
        """
        Get a monitoring configuration by ID.

        Args:
            config_id: ID of the config
            user_id: ID of the user (for authorization)

        Returns:
            MonitoringConfig: The monitoring config

        Raises:
            HTTPException: If config not found
        """
        config = self.db.query(MonitoringConfig).filter(
            MonitoringConfig.id == config_id,
            MonitoringConfig.user_id == user_id
        ).first()

        if not config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Monitoring configuration not found"
            )

        return config

    def get_monitoring_config_for_website(
        self,
        website_id: UUID,
        user_id: UUID,
    ) -> Optional[MonitoringConfig]:
        """
        Get the monitoring configuration for a website.

        Args:
            website_id: ID of the website
            user_id: ID of the user (for authorization)

        Returns:
            Optional[MonitoringConfig]: The monitoring config or None
        """
        config = self.db.query(MonitoringConfig).filter(
            MonitoringConfig.website_id == website_id,
            MonitoringConfig.user_id == user_id,
            MonitoringConfig.is_active == True
        ).first()

        return config

    def get_all_monitoring_configs(
        self,
        user_id: UUID,
        skip: int = 0,
        limit: int = 100,
    ) -> List[MonitoringConfig]:
        """
        Get all monitoring configurations for a user.

        Args:
            user_id: ID of the user
            skip: Number of records to skip
            limit: Maximum records to return

        Returns:
            List[MonitoringConfig]: List of monitoring configs
        """
        return self.db.query(MonitoringConfig).filter(
            MonitoringConfig.user_id == user_id,
            MonitoringConfig.is_active == True
        ).order_by(
            MonitoringConfig.next_run_at.asc()
        ).offset(skip).limit(limit).all()

    def update_monitoring_config(
        self,
        config_id: UUID,
        user_id: UUID,
        update_data: Dict[str, Any],
    ) -> MonitoringConfig:
        """
        Update a monitoring configuration.

        Args:
            config_id: ID of the config
            user_id: ID of the user (for authorization)
            update_data: Data to update

        Returns:
            MonitoringConfig: The updated config

        Raises:
            HTTPException: If config not found
        """
        config = self.get_monitoring_config(config_id, user_id)

        # Update fields
        if "frequency" in update_data:
            config.frequency = update_data["frequency"]

        if "scan_type" in update_data:
            config.scan_type = update_data["scan_type"]

        if "time_of_day" in update_data:
            try:
                hours, minutes = map(int, update_data["time_of_day"].split(":"))
                config.time_of_day = time(hours, minutes)
            except (ValueError, TypeError):
                pass

        if "day_of_week" in update_data:
            config.day_of_week = update_data["day_of_week"]

        if "day_of_month" in update_data:
            config.day_of_month = update_data["day_of_month"]

        if "notification_channels" in update_data:
            config.notification_channels = update_data["notification_channels"]

        if "max_failures" in update_data:
            config.max_failures = update_data["max_failures"]

        # Recalculate next run
        config.next_run_at = self._calculate_next_run(config)

        config.updated_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(config)

        # Log the update
        self._log_audit_event(
            user_id=user_id,
            action="monitoring_update",
            resource_type="monitoring_config",
            resource_id=str(config.id),
            details={"updated_fields": list(update_data.keys())},
        )

        return config

    def disable_monitoring(self, config_id: UUID, user_id: UUID) -> MonitoringConfig:
        """
        Disable monitoring for a website.

        Args:
            config_id: ID of the config
            user_id: ID of the user (for authorization)

        Returns:
            MonitoringConfig: The updated config

        Raises:
            HTTPException: If config not found
        """
        config = self.get_monitoring_config(config_id, user_id)
        config.disable()
        config.updated_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(config)

        # Log the action
        self._log_audit_event(
            user_id=user_id,
            action="monitoring_disable",
            resource_type="monitoring_config",
            resource_id=str(config.id),
            details={"website_id": str(config.website_id)},
        )

        return config

    def enable_monitoring(self, config_id: UUID, user_id: UUID) -> MonitoringConfig:
        """
        Enable monitoring for a website.

        Args:
            config_id: ID of the config
            user_id: ID of the user (for authorization)

        Returns:
            MonitoringConfig: The updated config

        Raises:
            HTTPException: If config not found
        """
        config = self.get_monitoring_config(config_id, user_id)
        config.enable()
        config.next_run_at = self._calculate_next_run(config)
        config.updated_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(config)

        return config

    def delete_monitoring_config(self, config_id: UUID, user_id: UUID) -> None:
        """
        Delete a monitoring configuration.

        Args:
            config_id: ID of the config
            user_id: ID of the user (for authorization)

        Raises:
            HTTPException: If config not found
        """
        config = self.get_monitoring_config(config_id, user_id)
        self.db.delete(config)
        self.db.commit()

    # ================================================================
    # Monitoring Execution
    # ================================================================

    async def run_monitoring_job(self, config_id: UUID) -> Dict[str, Any]:
        """
        Execute a monitoring scan for a website.

        Args:
            config_id: ID of the monitoring config

        Returns:
            Dict[str, Any]: Job result
        """
        config = self.db.query(MonitoringConfig).filter(
            MonitoringConfig.id == config_id,
            MonitoringConfig.is_active == True
        ).first()

        if not config:
            return {"status": "skipped", "reason": "Config not found or inactive"}

        # Check if should run
        if config.next_run_at and config.next_run_at > datetime.utcnow():
            return {"status": "skipped", "reason": "Not yet scheduled"}

        try:
            # Create scan
            scan = self.scan_service.create_scan(
                website_id=config.website_id,
                user_id=config.user_id,
                scan_data={"scan_type": config.scan_type},
            )

            # Start scan
            await self.scan_service.start_scan(scan.id, config.user_id)

            # Record success
            config.record_success()
            config.last_run_at = datetime.utcnow()
            config.next_run_at = self._calculate_next_run(config)
            self.db.commit()

            return {
                "status": "success",
                "scan_id": str(scan.id),
                "website_id": str(config.website_id),
            }

        except Exception as e:
            # Record failure
            config.record_failure()
            config.next_run_at = self._calculate_next_run(config)
            self.db.commit()

            # If too many failures, disable monitoring
            if config.failure_count >= config.max_failures:
                config.disable()
                self.db.commit()

                # Send alert
                website = self.db.query(Website).filter(
                    Website.id == config.website_id
                ).first()
                if website:
                    self.alert_service.trigger_monitoring_disabled_alert(website)

            return {
                "status": "failed",
                "error": str(e),
                "website_id": str(config.website_id),
            }

    async def run_all_monitoring_jobs(self) -> List[Dict[str, Any]]:
        """
        Run all due monitoring jobs.

        Returns:
            List[Dict[str, Any]]: Results of all jobs
        """
        # Get all configs due for execution
        configs = self.db.query(MonitoringConfig).filter(
            MonitoringConfig.is_active == True,
            MonitoringConfig.next_run_at <= datetime.utcnow()
        ).all()

        results = []
        for config in configs:
            result = await self.run_monitoring_job(config.id)
            results.append(result)

        return results

    # ================================================================
    # Schedule Calculation
    # ================================================================

    def _calculate_next_run(self, config: MonitoringConfig) -> datetime:
        """
        Calculate the next run time for a monitoring config.

        Args:
            config: The monitoring config

        Returns:
            datetime: The next run time
        """
        now = datetime.utcnow()
        base_time = now

        # Start from today at the configured time
        if config.time_of_day:
            base_time = datetime.combine(
                now.date(),
                config.time_of_day,
                tzinfo=None
            )
        else:
            base_time = datetime.combine(
                now.date(),
                time(0, 0),
                tzinfo=None
            )

        # If the time has already passed today, start from tomorrow
        if base_time <= now:
            base_time += timedelta(days=1)

        if config.frequency == "daily":
            return base_time

        elif config.frequency == "weekly":
            if config.day_of_week is not None:
                # Find the next occurrence of the specified day
                days_until = (config.day_of_week - now.weekday()) % 7
                if days_until == 0 and now > base_time:
                    days_until = 7
                return base_time + timedelta(days=days_until)
            return base_time + timedelta(days=7)

        elif config.frequency == "monthly":
            if config.day_of_month is not None:
                # Find the next occurrence of the specified day
                target_day = min(config.day_of_month, 28)  # Cap at 28 to avoid month issues
                if now.day < target_day or (now.day == target_day and now <= base_time):
                    return datetime.combine(
                        now.replace(day=target_day).date(),
                        config.time_of_day or time(0, 0),
                        tzinfo=None
                    )
                else:
                    # Next month
                    next_month = now.replace(day=1) + timedelta(days=32)
                    return datetime.combine(
                        next_month.replace(day=target_day).date(),
                        config.time_of_day or time(0, 0),
                        tzinfo=None
                    )
            return base_time + timedelta(days=30)

        elif config.frequency == "custom":
            if config.interval:
                return now + timedelta(days=config.interval)
            return now + timedelta(days=7)

        else:
            return now + timedelta(days=7)

    # ================================================================
    # Monitoring Status
    # ================================================================

    def get_monitoring_status(self, user_id: UUID) -> Dict[str, Any]:
        """
        Get monitoring status for a user.

        Args:
            user_id: ID of the user

        Returns:
            Dict[str, Any]: Monitoring status
        """
        configs = self.get_all_monitoring_configs(user_id)

        active_count = len([c for c in configs if c.is_active])
        disabled_count = len([c for c in configs if not c.is_active])

        return {
            "total_configs": len(configs),
            "active": active_count,
            "disabled": disabled_count,
            "upcoming_scans": [
                {
                    "website_id": str(c.website_id),
                    "next_run": c.next_run_at.isoformat() if c.next_run_at else None,
                    "frequency": c.frequency,
                }
                for c in configs[:5]
                if c.is_active and c.next_run_at
            ],
        }

    def get_website_monitoring_status(self, website_id: UUID, user_id: UUID) -> Dict[str, Any]:
        """
        Get monitoring status for a specific website.

        Args:
            website_id: ID of the website
            user_id: ID of the user (for authorization)

        Returns:
            Dict[str, Any]: Monitoring status
        """
        config = self.get_monitoring_config_for_website(website_id, user_id)

        if not config:
            return {
                "website_id": str(website_id),
                "configured": False,
                "status": "not_configured",
            }

        # Get recent scans
        recent_scans = self.db.query(Scan).filter(
            Scan.website_id == website_id,
            Scan.scan_type.in_(["full", "quick"]),
            Scan.status == "completed"
        ).order_by(
            Scan.created_at.desc()
        ).limit(5).all()

        return {
            "website_id": str(website_id),
            "configured": True,
            "config_id": str(config.id),
            "status": "active" if config.is_active else "disabled",
            "frequency": config.frequency,
            "scan_type": config.scan_type,
            "next_run_at": config.next_run_at.isoformat() if config.next_run_at else None,
            "last_run_at": config.last_run_at.isoformat() if config.last_run_at else None,
            "failure_count": config.failure_count,
            "max_failures": config.max_failures,
            "recent_scans": [
                {
                    "id": str(s.id),
                    "status": s.status,
                    "score": s.score,
                    "created_at": s.created_at.isoformat(),
                }
                for s in recent_scans
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