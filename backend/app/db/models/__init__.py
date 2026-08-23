"""
Database models for Sentinel.

This module defines all database tables using SQLAlchemy ORM.
"""

from app.db.models.user import User
from app.db.models.organization import Organization, organization_users
from app.db.models.website import Website
from app.db.models.website_verification import WebsiteVerification
from app.db.models.scan import Scan
from app.db.models.scan_job import ScanJob
from app.db.models.alert import Alert
from app.db.models.monitoring_config import MonitoringConfig
from app.db.models.audit_log import AuditLog
from app.db.models.ai_analysis import AIAnalysis
from app.db.models.finding import Finding
from app.db.models.subscription import Subscription
from app.db.models.security_score import SecurityScore
from app.db.models.usage_record import UsageRecord
from app.db.models.report import Report

__all__ = [
    "User",
    "Organization",
    "organization_users",
    "Website",
    "WebsiteVerification",
    "Scan",
    "ScanJob",
    "Alert",
    "MonitoringConfig",
    "AuditLog",
    "AIAnalysis",
    "Finding",
    "Subscription",
    "SecurityScore",
    "UsageRecord",
    "Report",
]
