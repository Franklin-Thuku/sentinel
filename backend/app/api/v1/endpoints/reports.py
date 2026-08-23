"""
Report endpoints.

Handles report generation and management: generate, list, get, download, delete.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_active_user
from app.schemas.report import ReportResponse, ReportListResponse, ReportGenerateRequest
from app.services.report_service import ReportService
from app.services.scan_service import ScanService
from app.db.models.user import User
from app.db.models.report import Report

router = APIRouter()


@router.post(
    "/scans/{scan_id}/reports",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate report",
)
async def generate_report(
    scan_id: UUID,
    request: Optional[ReportGenerateRequest] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Report:
    """
    Generate a security report for a scan.

    Args:
        scan_id: ID of the scan.
        request: Optional report generation request.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Report: The generated report.

    Raises:
        HTTPException: If scan not found or not completed.
    """
    # Check scan access
    scan_service = ScanService(db)
    scan = scan_service.get_scan(scan_id, current_user.id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot generate report for incomplete scan"
        )

    # Generate report
    service = ReportService(db)
    report = await service.generate_report(
        scan_id=scan_id,
        user_id=current_user.id,
        format=request.format if request else "pdf",
    )

    return report


@router.get(
    "/reports/{report_id}",
    response_model=ReportResponse,
    summary="Get report",
)
async def get_report(
    report_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Report:
    """
    Get a specific report by ID.

    Args:
        report_id: ID of the report.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Report: The report.

    Raises:
        HTTPException: If report not found.
    """
    service = ReportService(db)
    report = service.get_report(report_id, current_user.id)
    return report


@router.get(
    "/reports/{report_id}/download",
    summary="Download report",
)
async def download_report(
    report_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Download a report file.

    Args:
        report_id: ID of the report.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        FileResponse: The report file.

    Raises:
        HTTPException: If report not found or file missing.
    """
    service = ReportService(db)
    report = service.get_report(report_id, current_user.id)

    if not report.file_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found"
        )

    # Get file content
    content = service.get_report_content(report_id, current_user.id)

    # Determine content type
    content_type = "application/pdf"
    if report.format == "html":
        content_type = "text/html"
    elif report.format == "docx":
        content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    # Return file response
    return FileResponse(
        path=report.file_path,
        filename=f"security_report_{report.scan_id}.{report.format}",
        media_type=content_type,
    )


@router.get(
    "/scans/{scan_id}/reports",
    response_model=ReportListResponse,
    summary="List reports for a scan",
)
async def list_reports_for_scan(
    scan_id: UUID,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> ReportListResponse:
    """
    List all reports for a scan.

    Args:
        scan_id: ID of the scan.
        skip: Pagination offset.
        limit: Pagination limit.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        ReportListResponse: List of reports with pagination info.
    """
    # Check scan access
    scan_service = ScanService(db)
    scan = scan_service.get_scan(scan_id, current_user.id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    service = ReportService(db)
    reports = service.get_reports_for_scan(scan_id, current_user.id)

    # Get total count
    total = len(reports)

    # Apply pagination
    paginated_reports = reports[skip:skip + limit]

    return ReportListResponse(
        items=paginated_reports,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/websites/{website_id}/reports",
    response_model=ReportListResponse,
    summary="List reports for a website",
)
async def list_reports_for_website(
    website_id: UUID,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> ReportListResponse:
    """
    List all reports for a website.

    Args:
        website_id: ID of the website.
        skip: Pagination offset.
        limit: Pagination limit.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        ReportListResponse: List of reports with pagination info.
    """
    # Check website access
    from app.api.deps import get_website_or_404
    website = get_website_or_404(website_id, current_user, db)

    service = ReportService(db)
    reports = service.get_reports_for_website(website_id, current_user.id)

    # Get total count
    total = len(reports)

    # Apply pagination
    paginated_reports = reports[skip:skip + limit]

    return ReportListResponse(
        items=paginated_reports,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/reports",
    response_model=ReportListResponse,
    summary="List all reports",
)
async def list_all_reports(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> ReportListResponse:
    """
    List all reports for the current user.

    Args:
        skip: Pagination offset.
        limit: Pagination limit.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        ReportListResponse: List of reports with pagination info.
    """
    # Get all reports for user
    reports = db.query(Report).filter(
        Report.user_id == current_user.id
    ).order_by(
        Report.created_at.desc()
    ).offset(skip).limit(limit).all()

    # Get total count
    total = db.query(Report).filter(
        Report.user_id == current_user.id
    ).count()

    return ReportListResponse(
        items=reports,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.delete(
    "/reports/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete report",
)
async def delete_report(
    report_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> None:
    """
    Delete a report.

    Args:
        report_id: ID of the report.
        current_user: The authenticated user.
        db: Database session.

    Raises:
        HTTPException: If report not found.
    """
    service = ReportService(db)
    service.delete_report(report_id, current_user.id)


@router.get(
    "/reports/stats",
    response_model=dict,
    summary="Get report statistics",
)
async def get_report_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get report statistics for the current user.

    Args:
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Report statistics.
    """
    service = ReportService(db)
    stats = service.get_report_stats(current_user.id)
    return stats