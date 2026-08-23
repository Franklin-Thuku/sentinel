"""
Alert endpoints.

Handles alert management: list, get, mark read/unread, dismiss, restore.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_active_user
from app.schemas.alert import AlertResponse, AlertListResponse, AlertUpdate
from app.services.alert_service import AlertService
from app.db.models.user import User
from app.db.models.alert import Alert

router = APIRouter()


@router.get(
    "/",
    response_model=AlertListResponse,
    summary="List alerts",
)
async def list_alerts(
    is_read: Optional[bool] = Query(None, description="Filter by read status"),
    is_dismissed: Optional[bool] = Query(None, description="Filter by dismissed status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    """
    List all alerts for the current user.

    Args:
        is_read: Optional read status filter.
        is_dismissed: Optional dismissed status filter.
        severity: Optional severity filter.
        skip: Pagination offset.
        limit: Pagination limit.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        AlertListResponse: List of alerts with pagination info.
    """
    service = AlertService(db)
    alerts = service.get_alerts(
        user_id=current_user.id,
        is_read=is_read,
        is_dismissed=is_dismissed,
        severity=severity,
        skip=skip,
        limit=limit,
    )

    total = db.query(Alert).filter(
        Alert.user_id == current_user.id
    ).count()

    return AlertListResponse(
        items=alerts,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/active",
    response_model=List[AlertResponse],
    summary="Get active alerts",
)
async def get_active_alerts(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> List[Alert]:
    """
    Get active alerts (unread and not dismissed) for the current user.

    Args:
        current_user: The authenticated user.
        db: Database session.

    Returns:
        List[Alert]: List of active alerts.
    """
    service = AlertService(db)
    alerts = service.get_active_alerts(current_user.id)
    return alerts


@router.get(
    "/unread-count",
    response_model=dict,
    summary="Get unread alert count",
)
async def get_unread_count(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get the count of unread alerts for the current user.

    Args:
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Unread count.
    """
    service = AlertService(db)
    count = service.get_unread_count(current_user.id)
    return {"unread_count": count}


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get alert",
)
async def get_alert(
    alert_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Alert:
    """
    Get a specific alert by ID.

    Args:
        alert_id: ID of the alert.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Alert: The alert.

    Raises:
        HTTPException: If alert not found.
    """
    service = AlertService(db)
    alert = service.get_alert_by_id(alert_id, current_user.id)
    return alert


@router.patch(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Update alert",
)
async def update_alert(
    alert_id: UUID,
    update_data: AlertUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Alert:
    """
    Update an alert (mark read/dismissed).

    Args:
        alert_id: ID of the alert.
        update_data: Update data.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Alert: The updated alert.

    Raises:
        HTTPException: If alert not found.
    """
    alert = AlertService(db).get_alert_by_id(alert_id, current_user.id)

    if update_data.is_read is not None:
        if update_data.is_read:
            alert.mark_read()
        else:
            alert.mark_unread()

    if update_data.is_dismissed is not None:
        if update_data.is_dismissed:
            alert.dismiss()
        else:
            alert.restore()

    db.commit()
    db.refresh(alert)

    return alert


@router.post(
    "/{alert_id}/read",
    response_model=AlertResponse,
    summary="Mark alert as read",
)
async def mark_alert_read(
    alert_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Alert:
    """
    Mark an alert as read.

    Args:
        alert_id: ID of the alert.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Alert: The updated alert.
    """
    service = AlertService(db)
    alert = service.mark_read(alert_id, current_user.id)
    return alert


@router.post(
    "/{alert_id}/unread",
    response_model=AlertResponse,
    summary="Mark alert as unread",
)
async def mark_alert_unread(
    alert_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Alert:
    """
    Mark an alert as unread.

    Args:
        alert_id: ID of the alert.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Alert: The updated alert.
    """
    service = AlertService(db)
    alert = service.mark_unread(alert_id, current_user.id)
    return alert


@router.post(
    "/{alert_id}/dismiss",
    response_model=AlertResponse,
    summary="Dismiss alert",
)
async def dismiss_alert(
    alert_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Alert:
    """
    Dismiss an alert.

    Args:
        alert_id: ID of the alert.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Alert: The updated alert.
    """
    service = AlertService(db)
    alert = service.dismiss_alert(alert_id, current_user.id)
    return alert


@router.post(
    "/{alert_id}/restore",
    response_model=AlertResponse,
    summary="Restore dismissed alert",
)
async def restore_alert(
    alert_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Alert:
    """
    Restore a dismissed alert.

    Args:
        alert_id: ID of the alert.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Alert: The updated alert.
    """
    service = AlertService(db)
    alert = service.restore_alert(alert_id, current_user.id)
    return alert


@router.post(
    "/mark-all-read",
    response_model=dict,
    summary="Mark all alerts as read",
)
async def mark_all_read(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Mark all alerts as read for the current user.

    Args:
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Number of alerts marked as read.
    """
    service = AlertService(db)
    count = service.mark_all_read(current_user.id)
    return {"message": f"{count} alerts marked as read", "count": count}


@router.post(
    "/dismiss-all",
    response_model=dict,
    summary="Dismiss all alerts",
)
async def dismiss_all_alerts(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Dismiss all alerts for the current user.

    Args:
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Number of alerts dismissed.
    """
    service = AlertService(db)
    count = service.dismiss_all(current_user.id)
    return {"message": f"{count} alerts dismissed", "count": count}


@router.delete(
    "/{alert_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete alert",
)
async def delete_alert(
    alert_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> None:
    """
    Delete an alert permanently.

    Args:
        alert_id: ID of the alert.
        current_user: The authenticated user.
        db: Database session.

    Raises:
        HTTPException: If alert not found.
    """
    service = AlertService(db)
    service.delete_alert(alert_id, current_user.id)


@router.get(
    "/stats",
    response_model=dict,
    summary="Get alert statistics",
)
async def get_alert_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get alert statistics for the current user.

    Args:
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Alert statistics.
    """
    service = AlertService(db)
    stats = service.get_alert_stats(current_user.id)
    return stats