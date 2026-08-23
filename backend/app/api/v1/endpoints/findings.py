"""
Findings endpoints.

Handles finding management: list, get, update status, and AI analysis.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_active_user, get_website_or_404
from app.schemas.finding import FindingResponse, FindingUpdate, FindingListResponse
from app.services.scan_service import ScanService
from app.services.ai_service import AIService
from app.db.models.user import User
from app.db.models.finding import Finding

router = APIRouter()


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get finding",
)
async def get_finding(
    finding_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Finding:
    """
    Get a specific finding by ID.

    Args:
        finding_id: ID of the finding.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Finding: The finding.

    Raises:
        HTTPException: If finding not found or not accessible.
    """
    finding = db.query(Finding).filter(
        Finding.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )

    # Check if user has access to this finding via scan
    scan_service = ScanService(db)
    scan = scan_service.get_scan(finding.scan_id, current_user.id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this finding"
        )

    return finding


@router.get(
    "/scans/{scan_id}/findings",
    response_model=FindingListResponse,
    summary="List findings for a scan",
)
async def list_findings_for_scan(
    scan_id: UUID,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    category: Optional[str] = Query(None, description="Filter by category"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> FindingListResponse:
    """
    List all findings for a scan.

    Args:
        scan_id: ID of the scan.
        severity: Optional severity filter.
        status_filter: Optional status filter.
        category: Optional category filter.
        skip: Pagination offset.
        limit: Pagination limit.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        FindingListResponse: List of findings with pagination info.
    """
    # Check scan access
    scan_service = ScanService(db)
    scan = scan_service.get_scan(scan_id, current_user.id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    # Build query
    query = db.query(Finding).filter(
        Finding.scan_id == scan_id
    )

    if severity:
        query = query.filter(Finding.severity == severity)

    if status_filter:
        query = query.filter(Finding.status == status_filter)

    if category:
        query = query.filter(Finding.category == category)

    # Get total count
    total = query.count()

    # Get findings with pagination
    findings = query.order_by(
        Finding.severity.desc(),
        Finding.created_at.desc()
    ).offset(skip).limit(limit).all()

    return FindingListResponse(
        items=findings,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/websites/{website_id}/findings",
    response_model=FindingListResponse,
    summary="List findings for a website",
)
async def list_findings_for_website(
    website_id: UUID,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    resolved: Optional[bool] = Query(None, description="Filter by resolved status"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> FindingListResponse:
    """
    List all findings for a website.

    Args:
        website_id: ID of the website.
        severity: Optional severity filter.
        status_filter: Optional status filter.
        resolved: Filter by resolved status (True/False).
        skip: Pagination offset.
        limit: Pagination limit.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        FindingListResponse: List of findings with pagination info.
    """
    # Check website access
    website = get_website_or_404(website_id, current_user, db)

    # Build query
    query = db.query(Finding).filter(
        Finding.website_id == website_id
    )

    if severity:
        query = query.filter(Finding.severity == severity)

    if status_filter:
        query = query.filter(Finding.status == status_filter)

    if resolved is not None:
        if resolved:
            query = query.filter(Finding.status.in_(["resolved", "false_positive", "wont_fix"]))
        else:
            query = query.filter(Finding.status.in_(["open", "acknowledged"]))

    # Get total count
    total = query.count()

    # Get findings with pagination
    findings = query.order_by(
        Finding.severity.desc(),
        Finding.created_at.desc()
    ).offset(skip).limit(limit).all()

    return FindingListResponse(
        items=findings,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Update finding",
)
async def update_finding(
    finding_id: UUID,
    update_data: FindingUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Finding:
    """
    Update a finding's status or details.

    Args:
        finding_id: ID of the finding.
        update_data: Update data.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Finding: The updated finding.

    Raises:
        HTTPException: If finding not found or not accessible.
    """
    finding = db.query(Finding).filter(
        Finding.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )

    # Check scan access
    scan_service = ScanService(db)
    scan = scan_service.get_scan(finding.scan_id, current_user.id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this finding"
        )

    # Update fields
    if update_data.status is not None:
        finding.status = update_data.status

    if update_data.remediation is not None:
        finding.remediation = update_data.remediation

    finding.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(finding)

    return finding


@router.post(
    "/{finding_id}/acknowledge",
    response_model=FindingResponse,
    summary="Acknowledge finding",
)
async def acknowledge_finding(
    finding_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Finding:
    """
    Acknowledge a finding (mark as acknowledged).

    Args:
        finding_id: ID of the finding.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Finding: The updated finding.
    """
    finding = await get_finding(finding_id, current_user, db)
    finding.acknowledge()
    finding.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(finding)
    return finding


@router.post(
    "/{finding_id}/resolve",
    response_model=FindingResponse,
    summary="Resolve finding",
)
async def resolve_finding(
    finding_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Finding:
    """
    Mark a finding as resolved.

    Args:
        finding_id: ID of the finding.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Finding: The updated finding.
    """
    finding = await get_finding(finding_id, current_user, db)
    finding.resolve()
    finding.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(finding)
    return finding


@router.post(
    "/{finding_id}/false-positive",
    response_model=FindingResponse,
    summary="Mark as false positive",
)
async def mark_false_positive(
    finding_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Finding:
    """
    Mark a finding as a false positive.

    Args:
        finding_id: ID of the finding.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Finding: The updated finding.
    """
    finding = await get_finding(finding_id, current_user, db)
    finding.mark_false_positive()
    finding.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(finding)
    return finding


@router.post(
    "/{finding_id}/reopen",
    response_model=FindingResponse,
    summary="Reopen finding",
)
async def reopen_finding(
    finding_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Finding:
    """
    Reopen a resolved finding.

    Args:
        finding_id: ID of the finding.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        Finding: The updated finding.
    """
    finding = await get_finding(finding_id, current_user, db)
    finding.reopen()
    finding.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(finding)
    return finding


@router.post(
    "/{finding_id}/analyze",
    response_model=dict,
    summary="Run AI analysis on finding",
)
async def analyze_finding(
    finding_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Run AI analysis on a finding.

    Args:
        finding_id: ID of the finding.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Analysis status.
    """
    # Check access
    finding = db.query(Finding).filter(
        Finding.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )

    scan_service = ScanService(db)
    scan = scan_service.get_scan(finding.scan_id, current_user.id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this finding"
        )

    # Check usage limit for AI analysis
    from app.api.deps import check_usage_limit
    await check_usage_limit("ai_analysis", 1, current_user, db)

    # Run AI analysis
    ai_service = AIService(db)
    analysis = await ai_service.analyze_finding(finding_id)

    return {
        "status": "success",
        "message": "AI analysis completed",
        "analysis_id": str(analysis.id),
    }


@router.get(
    "/{finding_id}/analysis",
    response_model=dict,
    summary="Get AI analysis for finding",
)
async def get_finding_analysis(
    finding_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get AI analysis for a finding.

    Args:
        finding_id: ID of the finding.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: AI analysis data.
    """
    # Check access
    finding = db.query(Finding).filter(
        Finding.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )

    scan_service = ScanService(db)
    scan = scan_service.get_scan(finding.scan_id, current_user.id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this finding"
        )

    # Get analysis
    ai_service = AIService(db)
    analysis = ai_service.get_analysis_for_finding(finding_id)

    if not analysis:
        return {
            "status": "not_found",
            "message": "No AI analysis available for this finding"
        }

    return {
        "status": "success",
        "analysis_id": str(analysis.id),
        "plain_explanation": analysis.plain_explanation,
        "risk_explanation": analysis.risk_explanation,
        "technical_explanation": analysis.technical_explanation,
        "business_impact": analysis.business_impact,
        "recommended_remediation": analysis.recommended_remediation,
        "developer_remediation": analysis.developer_remediation,
        "priority": analysis.priority,
        "confidence": analysis.confidence,
        "references": analysis.references,
    }


@router.get(
    "/websites/{website_id}/findings/stats",
    response_model=dict,
    summary="Get finding statistics for a website",
)
async def get_finding_stats(
    website_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get finding statistics for a website.

    Args:
        website_id: ID of the website.
        current_user: The authenticated user.
        db: Database session.

    Returns:
        dict: Finding statistics.
    """
    # Check website access
    website = get_website_or_404(website_id, current_user, db)

    # Get counts by severity
    severity_counts = {}
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = db.query(Finding).filter(
            Finding.website_id == website_id,
            Finding.severity == severity
        ).count()
        severity_counts[severity] = count

    # Get counts by status
    status_counts = {}
    for status in ["open", "acknowledged", "resolved", "false_positive", "wont_fix"]:
        count = db.query(Finding).filter(
            Finding.website_id == website_id,
            Finding.status == status
        ).count()
        status_counts[status] = count

    # Get total
    total = db.query(Finding).filter(
        Finding.website_id == website_id
    ).count()

    return {
        "website_id": str(website_id),
        "total": total,
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "open_count": status_counts.get("open", 0) + status_counts.get("acknowledged", 0),
        "resolved_count": status_counts.get("resolved", 0) + status_counts.get("false_positive", 0) + status_counts.get("wont_fix", 0),
    }


# Need to import datetime
from datetime import datetime