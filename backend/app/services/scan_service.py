"""
Scan service for Sentinel.

Handles scan operations: create, start, track, and complete scans.
"""

import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.db.models.scan import Scan
from app.db.models.scan_job import ScanJob
from app.db.models.website import Website
from app.db.models.user import User
from app.db.models.finding import Finding
from app.db.models.security_score import SecurityScore
from app.db.models.audit_log import AuditLog

from app.schemas.scan import ScanCreate, ScanResponse
from app.services.verification_service import VerificationService
from app.scanners.orchestrator import ScannerOrchestrator


class ScanService:
    """Service for scan-related operations."""

    def __init__(self, db: Session):
        """
        Initialize the scan service.

        Args:
            db: Database session
        """
        self.db = db

    # ================================================================
    # CRUD Operations
    # ================================================================

    def create_scan(
        self,
        website_id: UUID,
        user_id: UUID,
        scan_data: Optional[ScanCreate] = None,
    ) -> Scan:
        """
        Create a new scan for a website.

        Args:
            website_id: ID of the website to scan
            user_id: ID of the user initiating the scan
            scan_data: Optional scan configuration

        Returns:
            Scan: The created scan record

        Raises:
            HTTPException: If website not found, not verified, or inactive
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
                detail="Website must be verified before scanning"
            )

        if not website.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Website is inactive"
            )

        # Check usage limits (simplified)
        self._check_scan_limits(user_id)

        # Create scan record
        scan = Scan(
            id=uuid.uuid4(),
            website_id=website_id,
            user_id=user_id,
            status="queued",
            scan_type=scan_data.scan_type if scan_data else "full",
        )

        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)

        # Log the scan creation
        self._log_audit_event(
            user_id=user_id,
            action="scan_start",
            resource_type="scan",
            resource_id=str(scan.id),
            details={
                "website_id": str(website_id),
                "scan_type": scan.scan_type,
            },
        )

        return scan

    def get_scan(self, scan_id: UUID, user_id: UUID) -> Optional[Scan]:
        """
        Get a specific scan by ID.

        Args:
            scan_id: ID of the scan
            user_id: ID of the user (for authorization)

        Returns:
            Optional[Scan]: The scan if found and owned by the user

        Raises:
            HTTPException: If scan not found
        """
        scan = self.db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == user_id
        ).first()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )

        return scan

    def get_scans_for_website(
        self,
        website_id: UUID,
        user_id: UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> List[Scan]:
        """
        Get all scans for a website.

        Args:
            website_id: ID of the website
            user_id: ID of the user (for authorization)
            skip: Number of records to skip
            limit: Maximum records to return

        Returns:
            List[Scan]: List of scans
        """
        return self.db.query(Scan).filter(
            Scan.website_id == website_id,
            Scan.user_id == user_id
        ).order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()

    def get_scans_for_user(
        self,
        user_id: UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> List[Scan]:
        """
        Get all scans for a user.

        Args:
            user_id: ID of the user
            skip: Number of records to skip
            limit: Maximum records to return

        Returns:
            List[Scan]: List of scans
        """
        return self.db.query(Scan).filter(
            Scan.user_id == user_id
        ).order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()

    # ================================================================
    # Scan Execution
    # ================================================================

    async def start_scan(self, scan_id: UUID, user_id: UUID) -> Scan:
        """
        Start a scan by triggering the scanning engine.

        Args:
            scan_id: ID of the scan to start
            user_id: ID of the user

        Returns:
            Scan: The updated scan

        Raises:
            HTTPException: If scan not found or already running
        """
        scan = self.get_scan(scan_id, user_id)

        if scan.status in ("running", "completed"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan is already {scan.status}"
            )

        # Update scan status
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(scan)

        # Log the scan start
        self._log_audit_event(
            user_id=user_id,
            action="scan_started",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"status": "running"},
        )

        # Run the scan
        try:
            results = await self._run_scan(scan)
            self._process_results(scan, results)
        except Exception as e:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            self.db.commit()

            # Log the failure
            self._log_audit_event(
                user_id=user_id,
                action="scan_failed",
                resource_type="scan",
                resource_id=str(scan.id),
                details={"error": str(e)},
            )

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Scan failed: {str(e)}"
            )

        return scan

    async def _run_scan(self, scan: Scan) -> Dict[str, Any]:
        """
        Run the actual scan using the scanner orchestrator.

        Args:
            scan: The scan record

        Returns:
            Dict[str, Any]: Scan results
        """
        # Get the website
        website = self.db.query(Website).filter(
            Website.id == scan.website_id
        ).first()

        if not website:
            raise ValueError(f"Website {scan.website_id} not found")

        # Initialize the orchestrator
        orchestrator = ScannerOrchestrator(website.url)

        # Run the scan
        results = await orchestrator.run_scan(scan.scan_type)

        return results

    def _process_results(self, scan: Scan, results: Dict[str, Any]) -> None:
        """
        Process scan results and store findings.

        Args:
            scan: The scan record
            results: The scan results from the orchestrator
        """
        # Store findings
        findings = results.get("findings", [])
        for finding_data in findings:
            finding = Finding(
                id=uuid.uuid4(),
                scan_id=scan.id,
                website_id=scan.website_id,
                category=finding_data.get("category", "other"),
                severity=finding_data.get("severity", "info"),
                title=finding_data.get("title", "Unknown Finding"),
                description=finding_data.get("description", ""),
                evidence=finding_data.get("evidence"),
                affected_url=finding_data.get("affected_url"),
                remediation=finding_data.get("remediation"),
                confidence=finding_data.get("confidence", 1.0),
                references=finding_data.get("references", []),
                scanner_module=finding_data.get("scanner_module"),
                status="open",
            )
            self.db.add(finding)

        # Store security score
        score_data = results.get("score", {})
        security_score = SecurityScore(
            id=uuid.uuid4(),
            scan_id=scan.id,
            website_id=scan.website_id,
            overall_score=score_data.get("overall_score", 0),
            grade=self._calculate_grade(score_data.get("overall_score", 0)),
            category_scores=score_data.get("category_scores", {}),
            score_factors=score_data.get("factors", {}),
            methodology_version="1.0",
            max_score=100,
        )
        self.db.add(security_score)

        # Update scan record
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.score = score_data.get("overall_score", 0)
        scan.findings_count = len(findings)

        # Update finding counts
        counts = self._count_findings_by_severity(findings)
        scan.critical_count = counts.get("critical", 0)
        scan.high_count = counts.get("high", 0)
        scan.medium_count = counts.get("medium", 0)
        scan.low_count = counts.get("low", 0)
        scan.info_count = counts.get("info", 0)

        # Update website
        website = self.db.query(Website).filter(
            Website.id == scan.website_id
        ).first()
        if website:
            website.last_scanned_at = datetime.utcnow()
            website.last_score = score_data.get("overall_score", 0)

        self.db.commit()

        # Log completion
        self._log_audit_event(
            user_id=scan.user_id,
            action="scan_completed",
            resource_type="scan",
            resource_id=str(scan.id),
            details={
                "findings_count": scan.findings_count,
                "score": scan.score,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
            },
        )

    # ================================================================
    # Helper Methods
    # ================================================================

    def _calculate_grade(self, score: int) -> str:
        """Calculate letter grade based on score."""
        if score >= 90:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 50:
            return "C"
        elif score >= 30:
            return "D"
        else:
            return "F"

    def _count_findings_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in counts:
                counts[severity] += 1
        return counts

    def _check_scan_limits(self, user_id: UUID) -> None:
        """
        Check if user has exceeded scan limits.

        Args:
            user_id: ID of the user

        Raises:
            HTTPException: If scan limit exceeded
        """
        # Count scans in the last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        scan_count = self.db.query(Scan).filter(
            Scan.user_id == user_id,
            Scan.created_at >= thirty_days_ago
        ).count()

        # Simplified limit (will be replaced with subscription-based limits)
        max_scans = 100  # Free tier limit

        if scan_count >= max_scans:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Scan limit exceeded. Maximum {max_scans} scans per month."
            )

    def get_scan_status(self, scan_id: UUID, user_id: UUID) -> dict:
        """
        Get the current status of a scan.

        Args:
            scan_id: ID of the scan
            user_id: ID of the user

        Returns:
            dict: Scan status information
        """
        scan = self.get_scan(scan_id, user_id)

        return {
            "id": str(scan.id),
            "status": scan.status,
            "progress": self._calculate_progress(scan),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "findings_count": scan.findings_count,
            "score": scan.score,
            "error_message": scan.error_message,
            "scan_type": scan.scan_type,
        }

    def _calculate_progress(self, scan: Scan) -> float:
        """Calculate scan progress as a percentage."""
        if scan.status == "queued":
            return 0.0
        elif scan.status == "running":
            # Estimate based on number of scanners (simplified)
            # In a real implementation, this would track job completion
            return 50.0
        elif scan.status == "completed":
            return 100.0
        elif scan.status == "failed":
            return 0.0
        else:
            return 0.0

    def get_scan_summary(self, scan_id: UUID, user_id: UUID) -> dict:
        """
        Get a summary of scan results.

        Args:
            scan_id: ID of the scan
            user_id: ID of the user

        Returns:
            dict: Scan summary
        """
        scan = self.get_scan(scan_id, user_id)

        return {
            "id": str(scan.id),
            "website_id": str(scan.website_id),
            "status": scan.status,
            "score": scan.score,
            "score_category": scan.score_category if scan.score else None,
            "findings_count": scan.findings_count,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
            "info_count": scan.info_count,
            "created_at": scan.created_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds,
        }

    def cancel_scan(self, scan_id: UUID, user_id: UUID) -> Scan:
        """
        Cancel a queued or running scan.

        Args:
            scan_id: ID of the scan
            user_id: ID of the user

        Returns:
            Scan: The cancelled scan

        Raises:
            HTTPException: If scan not found or cannot be cancelled
        """
        scan = self.get_scan(scan_id, user_id)

        if scan.status in ("completed", "failed", "cancelled"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan cannot be cancelled (status: {scan.status})"
            )

        scan.status = "cancelled"
        scan.completed_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(scan)

        # Log the cancellation
        self._log_audit_event(
            user_id=user_id,
            action="scan_cancel",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"status": "cancelled"},
        )

        return scan

    # ================================================================
    # Audit Logging
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


# Need to import timedelta at the top
from datetime import timedelta