"""
Database models for Sentinel.

This module defines all database tables using SQLAlchemy ORM.

All models inherit from `app.db.base.Base` and are automatically
discovered when creating tables or running migrations.

Models:
    - User: User accounts and authentication
    - Organization: Multi-tenant organization support
    - Website: Websites being monitored
    - WebsiteVerification: Proof of ownership
    - Scan: Scan records and metadata
    - ScanJob: Background job tracking
    - Finding: Security findings discovered during scans
    - AIAnalysis: AI-generated explanations for findings
    - SecurityScore: Calculated security scores
    - MonitoringConfig: Scheduled scan configurations
    - Alert: Security alerts for users
    - Report: Generated PDF reports
    - Subscription: User subscription plans
    - UsageRecord: Usage tracking for billing
    - AuditLog: Security audit trail
"""

# Import all models to register them with Base
# Order matters for foreign key references (dependencies first)
from app.db.models.user import User
from app.db.models.organization import Organization
from app.db.models.website import Website
from app.db.models.website_verification import WebsiteVerification
from app.db.models.scan import Scan
from app.db.models.scan_job import ScanJob
from app.db.models.finding import Finding
from app.db.models.ai_analysis import AIAnalysis
from app.db.models.security_score import SecurityScore
from app.db.models.monitoring_config import MonitoringConfig
from app.db.models.alert import Alert
from app.db.models.report import Report
from app.db.models.subscription import Subscription
from app.db.models.usage_record import UsageRecord
from app.db.models.audit_log import AuditLog

__all__ = [
    "User",
    "Organization",
    "Website",
    "WebsiteVerification",
    "Scan",
    "ScanJob",
    "Finding",
    "AIAnalysis",
    "SecurityScore",
    "MonitoringConfig",
    "Alert",
    "Report",
    "Subscription",
    "UsageRecord",
    "AuditLog",
]