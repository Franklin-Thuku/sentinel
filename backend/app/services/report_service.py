"""
Report service for Sentinel.

Handles generation and management of PDF security reports.
"""

import os
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from jinja2 import Environment, FileSystemLoader
import markdown

from app.config import settings
from app.db.models.report import Report
from app.db.models.scan import Scan
from app.db.models.finding import Finding
from app.db.models.website import Website
from app.db.models.user import User
from app.db.models.security_score import SecurityScore
from app.db.models.ai_analysis import AIAnalysis
from app.db.models.audit_log import AuditLog


class ReportService:
    """
    Service for report generation and management.

    Generates professional PDF security reports with:
    - Executive Summary
    - Security Score
    - Methodology
    - Findings
    - Risk Breakdown
    - Detailed Findings
    - Recommendations
    """

    def __init__(self, db: Session):
        """
        Initialize the report service.

        Args:
            db: Database session
        """
        self.db = db
        self.report_dir = os.path.join(os.getcwd(), "reports")
        self.template_dir = os.path.join(os.path.dirname(__file__), "..", "reports", "templates")

        # Ensure directories exist
        os.makedirs(self.report_dir, exist_ok=True)
        os.makedirs(self.template_dir, exist_ok=True)

        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=True,
        )

    # ================================================================
    # Report Generation
    # ================================================================

    async def generate_report(
        self,
        scan_id: UUID,
        user_id: UUID,
        format: str = "pdf",
    ) -> Report:
        """
        Generate a security report for a scan.

        Args:
            scan_id: ID of the scan
            user_id: ID of the user
            format: Report format (pdf, html)

        Returns:
            Report: The generated report record

        Raises:
            HTTPException: If scan not found or not completed
        """
        # Get scan
        scan = self.db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == user_id
        ).first()

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

        # Get website
        website = self.db.query(Website).filter(
            Website.id == scan.website_id
        ).first()

        # Get findings
        findings = self.db.query(Finding).filter(
            Finding.scan_id == scan_id
        ).order_by(
            Finding.severity.desc()
        ).all()

        # Get security score
        score = self.db.query(SecurityScore).filter(
            SecurityScore.scan_id == scan_id
        ).first()

        # Get AI analyses for findings
        ai_analyses = self.db.query(AIAnalysis).filter(
            AIAnalysis.scan_id == scan_id,
            AIAnalysis.status == "completed"
        ).all()

        # Create AI analysis lookup
        ai_lookup = {a.finding_id: a for a in ai_analyses}

        # Prepare report data
        report_data = self._prepare_report_data(
            scan=scan,
            website=website,
            findings=findings,
            score=score,
            ai_lookup=ai_lookup,
        )

        # Generate report content
        if format == "pdf":
            content = await self._generate_pdf(report_data)
            file_extension = ".pdf"
        else:
            content = self._generate_html(report_data)
            file_extension = ".html"

        # Save report
        filename = f"security_report_{scan_id}{file_extension}"
        file_path = os.path.join(self.report_dir, filename)
        file_hash = hashlib.sha256(content).hexdigest()

        with open(file_path, "wb") as f:
            f.write(content)

        # Create report record
        report = Report(
            id=uuid.uuid4(),
            scan_id=scan_id,
            website_id=scan.website_id,
            user_id=user_id,
            title=f"Security Report - {website.name if website else scan.website_id}",
            description=f"Security report for {website.name if website else scan.website_id}",
            file_path=file_path,
            file_size=len(content),
            file_hash=file_hash,
            format=format,
            template_version="1.0",
            status="completed",
            sections=self._get_report_sections(),
            settings={"include_ai_analysis": True, "format": format},
            expires_at=datetime.utcnow() + timedelta(days=30),
            completed_at=datetime.utcnow(),
        )

        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        # Log the report generation
        self._log_audit_event(
            user_id=user_id,
            action="report_generate",
            resource_type="report",
            resource_id=str(report.id),
            details={
                "scan_id": str(scan_id),
                "format": format,
                "findings_count": len(findings),
            },
        )

        return report

    def _prepare_report_data(
        self,
        scan: Scan,
        website: Optional[Website],
        findings: List[Finding],
        score: Optional[SecurityScore],
        ai_lookup: Dict[UUID, AIAnalysis],
    ) -> Dict[str, Any]:
        """
        Prepare data for the report.

        Args:
            scan: The scan
            website: The website
            findings: List of findings
            score: The security score
            ai_lookup: Lookup of AI analyses

        Returns:
            Dict[str, Any]: Report data
        """
        # Count findings by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1

        # Get AI analyses for findings
        ai_analyses = [
            {
                "finding": f,
                "analysis": ai_lookup.get(f.id),
            }
            for f in findings
            if f.id in ai_lookup
        ]

        return {
            "scan_id": str(scan.id),
            "website": {
                "id": str(website.id) if website else None,
                "url": website.url if website else "Unknown",
                "name": website.name if website else "Unknown",
                "domain": website.domain if website else "Unknown",
                "is_verified": website.is_verified if website else False,
            },
            "scan": {
                "status": scan.status,
                "scan_type": scan.scan_type,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration_seconds": scan.duration_seconds,
            },
            "score": {
                "overall_score": score.overall_score if score else None,
                "grade": score.grade if score else "N/A",
                "category_scores": score.category_scores if score else {},
            },
            "findings": [
                {
                    "id": str(f.id),
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "affected_url": f.affected_url,
                    "remediation": f.remediation,
                    "confidence": f.confidence,
                    "category": f.category,
                    "scanner_module": f.scanner_module,
                    "status": f.status,
                }
                for f in findings
            ],
            "severity_counts": severity_counts,
            "total_findings": len(findings),
            "ai_analyses": ai_analyses,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def _get_report_sections(self) -> List[str]:
        """Get the list of report sections."""
        return [
            "executive_summary",
            "security_score",
            "methodology",
            "findings_summary",
            "risk_breakdown",
            "detailed_findings",
            "recommendations",
            "technical_remediation",
            "appendix",
        ]

    # ================================================================
    # Report Generation - HTML/PDF
    # ================================================================

    def _generate_html(self, data: Dict[str, Any]) -> bytes:
        """
        Generate HTML report.

        Args:
            data: Report data

        Returns:
            bytes: HTML content
        """
        template = self.jinja_env.get_template("report_template.html")
        html_content = template.render(**data)
        return html_content.encode("utf-8")

    async def _generate_pdf(self, data: Dict[str, Any]) -> bytes:
        """
        Generate PDF report.

        Args:
            data: Report data

        Returns:
            bytes: PDF content
        """
        try:
            import weasyprint
            from weasyprint import HTML

            # Generate HTML first
            html_content = self._generate_html(data)

            # Convert to PDF
            pdf = HTML(string=html_content.decode("utf-8")).write_pdf()

            return pdf

        except ImportError:
            # Fallback to HTML if WeasyPrint not available
            return html_content

    # ================================================================
    # Report Retrieval
    # ================================================================

    def get_report(self, report_id: UUID, user_id: UUID) -> Report:
        """
        Get a report by ID.

        Args:
            report_id: ID of the report
            user_id: ID of the user (for authorization)

        Returns:
            Report: The report

        Raises:
            HTTPException: If report not found
        """
        report = self.db.query(Report).filter(
            Report.id == report_id,
            Report.user_id == user_id
        ).first()

        if not report:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found"
            )

        return report

    def get_reports_for_scan(self, scan_id: UUID, user_id: UUID) -> List[Report]:
        """
        Get all reports for a scan.

        Args:
            scan_id: ID of the scan
            user_id: ID of the user (for authorization)

        Returns:
            List[Report]: List of reports
        """
        return self.db.query(Report).filter(
            Report.scan_id == scan_id,
            Report.user_id == user_id
        ).order_by(
            Report.created_at.desc()
        ).all()

    def get_reports_for_website(self, website_id: UUID, user_id: UUID) -> List[Report]:
        """
        Get all reports for a website.

        Args:
            website_id: ID of the website
            user_id: ID of the user (for authorization)

        Returns:
            List[Report]: List of reports
        """
        return self.db.query(Report).filter(
            Report.website_id == website_id,
            Report.user_id == user_id
        ).order_by(
            Report.created_at.desc()
        ).all()

    def get_report_content(self, report_id: UUID, user_id: UUID) -> bytes:
        """
        Get the report file content.

        Args:
            report_id: ID of the report
            user_id: ID of the user (for authorization)

        Returns:
            bytes: The report content

        Raises:
            HTTPException: If report not found or file missing
        """
        report = self.get_report(report_id, user_id)

        if not report.file_path or not os.path.exists(report.file_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report file not found"
            )

        # Record download
        report.record_download()
        self.db.commit()

        # Log the download
        self._log_audit_event(
            user_id=user_id,
            action="report_download",
            resource_type="report",
            resource_id=str(report_id),
            details={"download_count": report.download_count},
        )

        with open(report.file_path, "rb") as f:
            return f.read()

    # ================================================================
    # Report Management
    # ================================================================

    def delete_report(self, report_id: UUID, user_id: UUID) -> None:
        """
        Delete a report.

        Args:
            report_id: ID of the report
            user_id: ID of the user (for authorization)

        Raises:
            HTTPException: If report not found
        """
        report = self.get_report(report_id, user_id)

        # Delete file if exists
        if report.file_path and os.path.exists(report.file_path):
            os.remove(report.file_path)

        self.db.delete(report)
        self.db.commit()

    def cleanup_expired_reports(self) -> int:
        """
        Clean up expired reports.

        Returns:
            int: Number of reports cleaned up
        """
        now = datetime.utcnow()
        expired = self.db.query(Report).filter(
            Report.expires_at < now
        ).all()

        count = 0
        for report in expired:
            if report.file_path and os.path.exists(report.file_path):
                os.remove(report.file_path)
            self.db.delete(report)
            count += 1

        self.db.commit()
        return count

    def get_report_stats(self, user_id: UUID) -> Dict[str, Any]:
        """
        Get report statistics for a user.

        Args:
            user_id: ID of the user

        Returns:
            Dict[str, Any]: Report statistics
        """
        reports = self.db.query(Report).filter(
            Report.user_id == user_id
        ).all()

        total_downloads = sum(r.download_count for r in reports)

        return {
            "total_reports": len(reports),
            "total_downloads": total_downloads,
            "reports_this_month": len([
                r for r in reports
                if r.created_at > datetime.utcnow() - timedelta(days=30)
            ]),
            "latest_report": reports[0].created_at.isoformat() if reports else None,
        }

    # ================================================================
    # Helper Methods
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