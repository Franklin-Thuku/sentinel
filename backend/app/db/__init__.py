"""
Database module for Sentinel.

This module provides the database foundation, session management,
and exports all database models.

Exports:
    - Base: Declarative base for all models
    - engine: SQLAlchemy engine instance
    - SessionLocal: Session factory
    - get_db(): FastAPI dependency for database sessions
    - init_db(): Initialize database (development only)
    - drop_db(): Drop all tables (development only)
    - get_db_status(): Database health check

All models should be imported in `app.db.models` and registered here.
"""

from app.db.base import (
    Base,
    engine,
    SessionLocal,
    get_db,
    init_db,
    drop_db,
    get_db_status,
)

# Import models to register them with Base
# This ensures all models are discovered when creating tables
from app.db.models import (
    User,
    Website,
    WebsiteVerification,
    Scan,
    ScanJob,
    Finding,
    AIAnalysis,
    SecurityScore,
    MonitoringConfig,
    Alert,
    Report,
    Subscription,
    UsageRecord,
    AuditLog,
    Organization,
)

__all__ = [
    # Core database components
    "Base",
    "engine",
    "SessionLocal",
    "get_db",
    "init_db",
    "drop_db",
    "get_db_status",
    # Models
    "User",
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
    "Organization",
]