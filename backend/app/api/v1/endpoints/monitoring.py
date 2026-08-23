"""
Monitoring endpoints.

Handles monitoring configuration and management: create, list, get, update, disable, enable.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_active_user, get_website_or_404, check_usage_limit
from app.schemas.monitoring import MonitoringConfigCreate, MonitoringConfigUpdate, MonitoringConfigResponse, MonitoringConfigListResponse
from app.services.monitoring_service import MonitoringService
from app.db.models.user import User
from app.db.models.monitoring_config import MonitoringConfig
from app.api.deps import get_current_active_user, get_website_or_404, check_usage_limit, get_current_admin_user
router = APIRouter()


@router.post(
    "/websites/{website_id}/monitoring",
    response_model=MonitoringConfigResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create monitoring configuration",
)
async def create_monitoring_config(
    website_id: UUID,
    config_data: MonitoringConfigCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> MonitoringConfig:
    """
    Create a monitoring configuration for a website.

    Args:
        website_id: ID of the website.
        config_data: Monitoring configuration data.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        MonitoringConfig: The created monitoring configuration.

    Raises:
        HTTPException: If website not found or config already exists.
    """
    # Check website exists and is verified
    website = get_website_or_404(website_id, current_user, db)

    if not website.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Website must be verified before monitoring"
        )

    # Check usage limit for monitoring
    await check_usage_limit("monitoring_jobs", 1, current_user, db)

    service = MonitoringService(db)
    config = service.create_monitoring_config(
        website_id=website_id,
        user_id=current_user.id,
        frequency=config_data.frequency,
        scan_type=config_data.scan_type,
        time_of_day=config_data.time_of_day,
        day_of_week=config_data.day_of_week,
        day_of_month=config_data.day_of_month,
        notification_channels=config_data.notification_channels,
    )

    return config


@router.get(
    "/websites/{website_id}/monitoring",
    response_model=MonitoringConfigResponse,
    summary="Get monitoring configuration for website",
)
async def get_monitoring_config_for_website(
    website_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> MonitoringConfig:
    """
    Get the monitoring configuration for a website.

    Args:
        website_id: ID of the website.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        MonitoringConfig: The monitoring configuration.

    Raises:
        HTTPException: If website not found or no monitoring config exists.
    """
    # Check website exists
    get_website_or_404(website_id, current_user, db)

    service = MonitoringService(db)
    config = service.get_monitoring_config_for_website(website_id, current_user.id)

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitoring configuration not found for this website"
        )

    return config


@router.get(
    "/monitoring",
    response_model=MonitoringConfigListResponse,
    summary="List all monitoring configurations",
)
async def list_monitoring_configs(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> MonitoringConfigListResponse:
    """
    List all monitoring configurations for the current user.

    Args:
        skip: Pagination offset.
        limit: Pagination limit.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        MonitoringConfigListResponse: List of monitoring configs with pagination info.
    """
    service = MonitoringService(db)
    configs = service.get_all_monitoring_configs(
        user_id=current_user.id,
        skip=skip,
        limit=limit,
    )

    total = db.query(MonitoringConfig).filter(
        MonitoringConfig.user_id == current_user.id,
        MonitoringConfig.is_active == True
    ).count()

    return MonitoringConfigListResponse(
        items=configs,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/monitoring/{config_id}",
    response_model=MonitoringConfigResponse,
    summary="Get monitoring configuration",
)
async def get_monitoring_config(
    config_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> MonitoringConfig:
    """
    Get a specific monitoring configuration by ID.

    Args:
        config_id: ID of the monitoring configuration.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        MonitoringConfig: The monitoring configuration.

    Raises:
        HTTPException: If config not found.
    """
    service = MonitoringService(db)
    config = service.get_monitoring_config(config_id, current_user.id)
    return config


@router.put(
    "/monitoring/{config_id}",
    response_model=MonitoringConfigResponse,
    summary="Update monitoring configuration",
)
async def update_monitoring_config(
    config_id: UUID,
    update_data: MonitoringConfigUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> MonitoringConfig:
    """
    Update a monitoring configuration.

    Args:
        config_id: ID of the monitoring configuration.
        update_data: Update data.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        MonitoringConfig: The updated monitoring configuration.

    Raises:
        HTTPException: If config not found.
    """
    service = MonitoringService(db)
    config = service.update_monitoring_config(
        config_id=config_id,
        user_id=current_user.id,
        update_data=update_data.model_dump(exclude_unset=True),
    )
    return config


@router.post(
    "/monitoring/{config_id}/disable",
    response_model=MonitoringConfigResponse,
    summary="Disable monitoring",
)
async def disable_monitoring(
    config_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> MonitoringConfig:
    """
    Disable monitoring for a website.

    Args:
        config_id: ID of the monitoring configuration.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        MonitoringConfig: The updated monitoring configuration.

    Raises:
        HTTPException: If config not found.
    """
    service = MonitoringService(db)
    config = service.disable_monitoring(config_id, current_user.id)
    return config


@router.post(
    "/monitoring/{config_id}/enable",
    response_model=MonitoringConfigResponse,
    summary="Enable monitoring",
)
async def enable_monitoring(
    config_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> MonitoringConfig:
    """
    Enable monitoring for a website.

    Args:
        config_id: ID of the monitoring configuration.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        MonitoringConfig: The updated monitoring configuration.

    Raises:
        HTTPException: If config not found.
    """
    service = MonitoringService(db)
    config = service.enable_monitoring(config_id, current_user.id)
    return config


@router.delete(
    "/monitoring/{config_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete monitoring configuration",
)
async def delete_monitoring_config(
    config_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> None:
    """
    Delete a monitoring configuration.

    Args:
        config_id: ID of the monitoring configuration.
        current_user: The authenticated user.
        db: Database session.

    Raises:
        HTTPException: If config not found.
    """
    service = MonitoringService(db)
    service.delete_monitoring_config(config_id, current_user.id)


@router.get(
    "/websites/{website_id}/monitoring/status",
    response_model=dict,
    summary="Get monitoring status for website",
)
async def get_website_monitoring_status(
    website_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get monitoring status for a website.

    Args:
        website_id: ID of the website.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Monitoring status.
    """
    service = MonitoringService(db)
    status = service.get_website_monitoring_status(website_id, current_user.id)
    return status


@router.get(
    "/status",
    response_model=dict,
    summary="Get overall monitoring status",
)
async def get_monitoring_status(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get overall monitoring status for the current user.

    Args:
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Monitoring status.
    """
    service = MonitoringService(db)
    status = service.get_monitoring_status(current_user.id)
    return status


@router.post(
    "/monitoring/run",
    response_model=dict,
    summary="Run all due monitoring jobs",
)
async def run_monitoring_jobs(
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Run all due monitoring jobs (admin only).

    Args:
        current_user: The authenticated admin user.
        db: Database session.

    Returns:
        dict: Job execution results.
    """
    service = MonitoringService(db)
    results = await service.run_all_monitoring_jobs()
    return {
        "message": f"Ran {len(results)} monitoring jobs",
        "results": results,
    }