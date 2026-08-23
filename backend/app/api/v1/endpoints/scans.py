"""
Scan endpoints.

Handles scan management: create, list, get, status, and results.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_active_user, get_website_or_404, check_usage_limit
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse, ScanStatusResponse
from app.services.scan_service import ScanService
from app.services.website_service import WebsiteService
from app.db.models.user import User
from app.db.models.scan import Scan

router = APIRouter()


@router.post(
    "/{website_id}/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start a scan",
)
async def create_scan(
    website_id: UUID,
    scan_data: Optional[ScanCreate] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Scan:
    """
    Start a new scan for a website.

    Args:
        website_id: ID of the website to scan.
        scan_data: Optional scan configuration.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Scan: The created scan record.
    """
    # Check usage limit
    await check_usage_limit("scans", 1, current_user, db)

    # Check if website exists and is verified
    website_service = WebsiteService(db)
    website = website_service.get_website(website_id, current_user.id)

    if not website:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Website not found"
        )

    if not website.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Website must be verified before scanning"
        )

    service = ScanService(db)
    scan = service.create_scan(website_id, current_user.id, scan_data)
    return scan


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan details",
)
async def get_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Scan:
    """
    Get a specific scan by ID.

    Args:
        scan_id: ID of the scan.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Scan: The scan details.
    """
    service = ScanService(db)
    scan = service.get_scan(scan_id, current_user.id)
    return scan


@router.get(
    "/scans/{scan_id}/status",
    response_model=ScanStatusResponse,
    summary="Get scan status",
)
async def get_scan_status(
    scan_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get the current status of a scan.

    Args:
        scan_id: ID of the scan.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Scan status information.
    """
    service = ScanService(db)
    status = service.get_scan_status(scan_id, current_user.id)
    return status


@router.get(
    "/scans/{scan_id}/summary",
    response_model=dict,
    summary="Get scan summary",
)
async def get_scan_summary(
    scan_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get a summary of scan results.

    Args:
        scan_id: ID of the scan.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Scan summary.
    """
    service = ScanService(db)
    summary = service.get_scan_summary(scan_id, current_user.id)
    return summary


@router.get(
    "/{website_id}/scans",
    response_model=ScanListResponse,
    summary="List scans for website",
)
async def list_scans_for_website(
    website_id: UUID,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> ScanListResponse:
    """
    List all scans for a specific website.

    Args:
        website_id: ID of the website.
        skip: Pagination offset.
        limit: Pagination limit.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        ScanListResponse: List of scans with pagination info.
    """
    # Check website exists
    website_service = WebsiteService(db)
    website = website_service.get_website(website_id, current_user.id)

    if not website:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Website not found"
        )

    service = ScanService(db)
    scans = service.get_scans_for_website(
        website_id,
        current_user.id,
        skip=skip,
        limit=limit,
    )

    # Get total count
    total = db.query(Scan).filter(
        Scan.website_id == website_id,
        Scan.user_id == current_user.id
    ).count()

    return ScanListResponse(
        items=scans,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/scans",
    response_model=ScanListResponse,
    summary="List all scans for user",
)
async def list_all_scans(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> ScanListResponse:
    """
    List all scans for the current user.

    Args:
        skip: Pagination offset.
        limit: Pagination limit.
        status_filter: Optional status filter.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        ScanListResponse: List of scans with pagination info.
    """
    service = ScanService(db)
    scans = service.get_scans_for_user(current_user.id, skip=skip, limit=limit)

    # Apply status filter if provided
    if status_filter:
        scans = [s for s in scans if s.status == status_filter]

    # Get total count
    total = db.query(Scan).filter(
        Scan.user_id == current_user.id
    ).count()

    return ScanListResponse(
        items=scans,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancel a scan",
)
async def cancel_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Scan:
    """
    Cancel a queued or running scan.

    Args:
        scan_id: ID of the scan.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Scan: The cancelled scan.
    """
    service = ScanService(db)
    scan = service.cancel_scan(scan_id, current_user.id)
    return scan