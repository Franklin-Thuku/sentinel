"""
Admin endpoints.

Provides administrative functionality for system management:
- System health and monitoring
- User management (admin)
- Scan management (admin)
- System configuration
- Metrics and statistics
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db
from app.api.deps import get_current_super_admin_user, get_current_admin_user
from app.db.models.user import User
from app.db.models.website import Website
from app.db.models.scan import Scan
from app.db.models.finding import Finding
from app.db.models.organization import Organization
from app.db.models.subscription import Subscription
from app.db.models.alert import Alert
from app.services.user_service import UserService
from app.services.website_service import WebsiteService
from app.services.scan_service import ScanService
from app.services.subscription_service import SubscriptionService
from app.core.security import get_current_user
from app.config import settings

router = APIRouter()


# ================================================================
# System Health & Monitoring
# ================================================================

@router.get(
    "/health",
    summary="System health check",
    description="Admin only - check system health",
)
async def system_health(
    admin_user: User = Depends(get_current_super_admin_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get system health status.

    Args:
        admin_user: The authenticated super admin user.
        db: Database session.

    Returns:
        dict: System health status.
    """
    # Database health
    try:
        db.execute("SELECT 1")
        database_healthy = True
    except Exception:
        database_healthy = False

    # Count total users
    total_users = db.query(User).filter(
        User.deleted_at.is_(None)
    ).count()

    # Count active users (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    active_users = db.query(User).filter(
        User.last_login_at >= thirty_days_ago,
        User.deleted_at.is_(None)
    ).count()

    # Count total scans
    total_scans = db.query(Scan).count()

    # Count scans in last 24 hours
    yesterday = datetime.utcnow() - timedelta(hours=24)
    scans_24h = db.query(Scan).filter(
        Scan.created_at >= yesterday
    ).count()

    return {
        "status": "healthy" if database_healthy else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "database": {
            "healthy": database_healthy,
        },
        "statistics": {
            "total_users": total_users,
            "active_users_30d": active_users,
            "total_scans": total_scans,
            "scans_24h": scans_24h,
        },
    }


@router.get(
    "/stats",
    summary="System statistics",
    description="Admin only - get system statistics",
)
async def system_stats(
    admin_user: User = Depends(get_current_super_admin_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get detailed system statistics.

    Args:
        admin_user: The authenticated super admin user.
        db: Database session.

    Returns:
        dict: System statistics.
    """
    # User statistics
    total_users = db.query(User).filter(
        User.deleted_at.is_(None)
    ).count()

    users_by_role = {}
    for role in ["user", "admin", "super_admin"]:
        count = db.query(User).filter(
            User.role == role,
            User.deleted_at.is_(None)
        ).count()
        users_by_role[role] = count

    # Organization statistics
    total_orgs = db.query(Organization).filter(
        Organization.deleted_at.is_(None)
    ).count()

    # Website statistics
    total_websites = db.query(Website).filter(
        Website.deleted_at.is_(None)
    ).count()

    verified_websites = db.query(Website).filter(
        Website.is_verified == True,
        Website.deleted_at.is_(None)
    ).count()

    # Scan statistics
    total_scans = db.query(Scan).count()
    completed_scans = db.query(Scan).filter(
        Scan.status == "completed"
    ).count()
    failed_scans = db.query(Scan).filter(
        Scan.status == "failed"
    ).count()
    running_scans = db.query(Scan).filter(
        Scan.status == "running"
    ).count()

    # Finding statistics
    total_findings = db.query(Finding).count()
    critical_findings = db.query(Finding).filter(
        Finding.severity == "critical"
    ).count()
    high_findings = db.query(Finding).filter(
        Finding.severity == "high"
    ).count()

    # Subscription statistics
    subscriptions = db.query(Subscription).all()
    plan_counts = {}
    for sub in subscriptions:
        if sub.plan not in plan_counts:
            plan_counts[sub.plan] = 0
        plan_counts[sub.plan] += 1

    return {
        "users": {
            "total": total_users,
            "by_role": users_by_role,
        },
        "organizations": {
            "total": total_orgs,
        },
        "websites": {
            "total": total_websites,
            "verified": verified_websites,
        },
        "scans": {
            "total": total_scans,
            "completed": completed_scans,
            "failed": failed_scans,
            "running": running_scans,
        },
        "findings": {
            "total": total_findings,
            "critical": critical_findings,
            "high": high_findings,
        },
        "subscriptions": {
            "plan_counts": plan_counts,
            "total": len(subscriptions),
        },
    }


# ================================================================
# User Management (Admin)
# ================================================================

@router.get(
    "/users",
    summary="List all users",
    description="Admin only - list all users",
)
async def admin_list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None, description="Search by email or name"),
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    List all users (admin only).

    Args:
        skip: Pagination offset.
        limit: Pagination limit.
        search: Optional search term.
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        dict: List of users with pagination info.
    """
    query = db.query(User).filter(
        User.deleted_at.is_(None)
    )

    if search:
        query = query.filter(
            (User.email.ilike(f"%{search}%")) |
            (User.full_name.ilike(f"%{search}%"))
        )

    total = query.count()
    users = query.offset(skip).limit(limit).all()

    return {
        "items": users,
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get(
    "/users/{user_id}",
    summary="Get user details",
    description="Admin only - get user details",
)
async def admin_get_user(
    user_id: UUID,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> User:
    """
    Get user details (admin only).

    Args:
        user_id: ID of the user.
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        User: The user details.

    Raises:
        HTTPException: If user not found.
    """
    service = UserService(db)
    user = service.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user


@router.put(
    "/users/{user_id}/role",
    summary="Update user role",
    description="Admin only - update user role",
)
async def admin_update_user_role(
    user_id: UUID,
    role: str,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Update a user's role (admin only).

    Args:
        user_id: ID of the user.
        role: New role (user, admin).
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        dict: Success message.

    Raises:
        HTTPException: If user not found or role invalid.
    """
    if role not in ["user", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be 'user' or 'admin'"
        )

    service = UserService(db)
    user = service.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.role = role
    db.commit()

    return {
        "message": f"User role updated to {role}",
        "user_id": str(user_id),
        "role": role,
    }


@router.post(
    "/users/{user_id}/suspend",
    summary="Suspend user",
    description="Admin only - suspend a user account",
)
async def admin_suspend_user(
    user_id: UUID,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Suspend a user account (admin only).

    Args:
        user_id: ID of the user.
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        dict: Success message.

    Raises:
        HTTPException: If user not found.
    """
    service = UserService(db)
    user = service.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.role == "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot suspend a super admin"
        )

    user.is_active = False
    db.commit()

    return {
        "message": f"User {user.email} suspended",
        "user_id": str(user_id),
    }


@router.post(
    "/users/{user_id}/unsuspend",
    summary="Unsuspend user",
    description="Admin only - unsuspend a user account",
)
async def admin_unsuspend_user(
    user_id: UUID,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Unsuspend a user account (admin only).

    Args:
        user_id: ID of the user.
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        dict: Success message.

    Raises:
        HTTPException: If user not found.
    """
    service = UserService(db)
    user = service.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.is_active = True
    db.commit()

    return {
        "message": f"User {user.email} unsuspended",
        "user_id": str(user_id),
    }


# ================================================================
# System Configuration
# ================================================================

@router.get(
    "/config",
    summary="Get system configuration",
    description="Admin only - get system configuration (excluding secrets)",
)
async def admin_get_config(
    admin_user: User = Depends(get_current_super_admin_user),
) -> dict:
    """
    Get system configuration (admin only).

    Args:
        admin_user: The authenticated super admin user.

    Returns:
        dict: System configuration.
    """
    # Expose non-sensitive configuration
    return {
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "app_env": settings.APP_ENV,
        "api_v1_prefix": settings.API_V1_PREFIX,
        "cors_origins": settings.CORS_ORIGINS,
        "rate_limit_enabled": settings.RATE_LIMIT_ENABLED,
        "subscription_enabled": settings.SUBSCRIPTION_ENABLED,
        "scan_config": {
            "max_urls": settings.SCAN_MAX_URLS,
            "max_response_size": settings.SCAN_MAX_RESPONSE_SIZE,
            "request_timeout": settings.SCAN_REQUEST_TIMEOUT,
            "total_timeout": settings.SCAN_TOTAL_TIMEOUT,
            "max_redirects": settings.SCAN_MAX_REDIRECTS,
            "max_concurrent_requests": settings.SCAN_MAX_CONCURRENT_REQUESTS,
        },
        "ai_config": {
            "provider": settings.AI_PROVIDER,
            "model": settings.AI_MODEL,
        },
        "limits": {
            "free": {
                "websites": settings.FREE_WEBSITE_LIMIT,
                "scans_per_month": settings.FREE_SCAN_LIMIT_PER_MONTH,
            },
            "pro": {
                "websites": settings.PRO_WEBSITE_LIMIT,
                "scans_per_month": settings.PRO_SCAN_LIMIT_PER_MONTH,
            },
            "agency": {
                "websites": settings.AGENCY_WEBSITE_LIMIT,
                "scans_per_month": settings.AGENCY_SCAN_LIMIT_PER_MONTH,
            },
        },
    }


# ================================================================
# Scan Management (Admin)
# ================================================================

@router.get(
    "/scans",
    summary="List all scans",
    description="Admin only - list all scans",
)
async def admin_list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    List all scans (admin only).

    Args:
        skip: Pagination offset.
        limit: Pagination limit.
        status_filter: Optional status filter.
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        dict: List of scans with pagination info.
    """
    query = db.query(Scan)

    if status_filter:
        query = query.filter(Scan.status == status_filter)

    total = query.count()
    scans = query.order_by(
        Scan.created_at.desc()
    ).offset(skip).limit(limit).all()

    return {
        "items": scans,
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get(
    "/scans/{scan_id}",
    summary="Get scan details",
    description="Admin only - get scan details",
)
async def admin_get_scan(
    scan_id: UUID,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> Scan:
    """
    Get scan details (admin only).

    Args:
        scan_id: ID of the scan.
        admin_user: The authenticated admin user.
        db: Database session.

    Returns:
        Scan: The scan details.

    Raises:
        HTTPException: If scan not found.
    """
    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    return scan


# ================================================================
# Maintenance
# ================================================================

@router.post(
    "/maintenance/cleanup",
    summary="Clean up old data",
    description="Admin only - clean up old data",
)
async def admin_cleanup(
    retention_days: int = Query(90, ge=30, le=365, description="Days to retain"),
    admin_user: User = Depends(get_current_super_admin_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Clean up old data (admin only).

    Args:
        retention_days: Number of days to retain.
        admin_user: The authenticated super admin user.
        db: Database session.

    Returns:
        dict: Cleanup results.
    """
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

    # Clean up old audit logs
    from app.db.models.audit_log import AuditLog
    audit_deleted = db.query(AuditLog).filter(
        AuditLog.created_at < cutoff_date
    ).delete()

    # Clean up old alerts (kept for retention_days)
    alerts_deleted = db.query(Alert).filter(
        Alert.created_at < cutoff_date,
        Alert.is_dismissed == True
    ).delete()

    db.commit()

    return {
        "message": f"Cleanup completed",
        "audit_logs_deleted": audit_deleted,
        "alerts_deleted": alerts_deleted,
        "retention_days": retention_days,
    }


@router.post(
    "/maintenance/refresh-scores",
    summary="Refresh scores for all websites",
    description="Admin only - recalculate scores for all websites",
)
async def admin_refresh_scores(
    admin_user: User = Depends(get_current_super_admin_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Recalculate security scores for all websites (admin only).

    Args:
        admin_user: The authenticated super admin user.
        db: Database session.

    Returns:
        dict: Result message.
    """
    from app.services.score_service import ScoreService

    service = ScoreService(db)

    # Get all completed scans without scores
    scans = db.query(Scan).filter(
        Scan.status == "completed",
        Scan.score.is_(None)
    ).all()

    updated = 0
    for scan in scans:
        try:
            score = service.calculate_scan_score(scan.id)
            updated += 1
        except Exception:
            pass

    return {
        "message": f"Refreshed scores for {updated} scans",
        "total_scans_without_score": len(scans),
        "updated": updated,
    }