"""
Score service for Sentinel.

Calculates security scores based on findings from scans.
Transparent scoring methodology with category breakdowns.
"""

from typing import Dict, List, Any, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models.scan import Scan
from app.db.models.finding import Finding
from app.db.models.security_score import SecurityScore
from app.db.models.website import Website


class ScoreService:
    """
    Service for security score calculation.

    Scoring Methodology:
    - Base score starts at 100
    - Deductions based on severity and confidence
    - Category scores for different security areas
    - Weighted average for final score
    """

    # Severity weights (deduction points)
    SEVERITY_WEIGHTS = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 1,
    }

    # Category weights (percentage of total score)
    CATEGORY_WEIGHTS = {
        "headers": 20,
        "tls": 20,
        "dns": 10,
        "cookies": 10,
        "content": 10,
        "configuration": 10,
        "server": 10,
        "other": 10,
    }

    def __init__(self, db: Session):
        """
        Initialize the score service.

        Args:
            db: Database session
        """
        self.db = db

    # ================================================================
    # Score Calculation
    # ================================================================

    def calculate_scan_score(self, scan_id: UUID) -> SecurityScore:
        """
        Calculate the security score for a completed scan.

        Args:
            scan_id: ID of the scan

        Returns:
            SecurityScore: The calculated security score

        Raises:
            ValueError: If scan not found or not completed
        """
        # Get the scan
        scan = self.db.query(Scan).filter(
            Scan.id == scan_id
        ).first()

        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        if scan.status != "completed":
            raise ValueError(f"Scan {scan_id} is not completed")

        # Get all findings for this scan
        findings = self.db.query(Finding).filter(
            Finding.scan_id == scan_id
        ).all()

        # Calculate overall score
        overall_score, deductions = self._calculate_overall_score(findings)

        # Calculate category scores
        category_scores = self._calculate_category_scores(findings)

        # Calculate category breakdown
        breakdown = self._calculate_breakdown(findings)

        # Calculate score factors
        factors = self._calculate_factors(findings)

        # Get previous score for comparison
        previous_score = self._get_previous_score(scan.website_id)

        # Create security score record
        security_score = SecurityScore(
            scan_id=scan_id,
            website_id=scan.website_id,
            overall_score=overall_score,
            grade=self._calculate_grade(overall_score),
            category_scores=category_scores,
            score_factors=factors,
            weightings=self.CATEGORY_WEIGHTS,
            breakdown=breakdown,
            methodology_version="1.0",
            max_score=100,
            previous_score=previous_score,
            score_change=overall_score - previous_score if previous_score is not None else None,
        )

        self.db.add(security_score)
        self.db.commit()
        self.db.refresh(security_score)

        return security_score

    def _calculate_overall_score(
        self,
        findings: List[Finding]
    ) -> tuple[int, Dict[str, int]]:
        """
        Calculate the overall security score.

        Args:
            findings: List of findings

        Returns:
            tuple: (overall_score, deductions_by_severity)
        """
        # Start with perfect score
        base_score = 100

        # Track deductions by severity
        deductions = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        # Apply deductions
        for finding in findings:
            severity = finding.severity
            confidence = finding.confidence

            # Get base deduction for this severity
            base_deduction = self.SEVERITY_WEIGHTS.get(severity, 1)

            # Apply confidence factor (higher confidence = higher deduction)
            deduction = base_deduction * confidence

            # Cap deduction to 90% of severity weight maximum
            max_deduction = self.SEVERITY_WEIGHTS.get(severity, 1)
            deduction = min(deduction, max_deduction)

            # Apply (only deduct if score > 0)
            if severity in deductions:
                deductions[severity] += deduction

        # Calculate total deduction
        total_deduction = sum(deductions.values())

        # Calculate final score (minimum 0)
        final_score = max(0, int(base_score - total_deduction))

        return final_score, deductions

    def _calculate_category_scores(
        self,
        findings: List[Finding]
    ) -> Dict[str, int]:
        """
        Calculate scores by category.

        Args:
            findings: List of findings

        Returns:
            Dict[str, int]: Category scores
        """
        category_scores = {}

        # Group findings by category
        for finding in findings:
            category = finding.category
            if category not in category_scores:
                category_scores[category] = 100

            # Apply deduction within category
            deduction = self.SEVERITY_WEIGHTS.get(finding.severity, 1)
            category_scores[category] -= deduction * finding.confidence
            category_scores[category] = max(0, int(category_scores[category]))

        return category_scores

    def _calculate_breakdown(
        self,
        findings: List[Finding]
    ) -> Dict[str, Any]:
        """
        Calculate detailed score breakdown.

        Args:
            findings: List of findings

        Returns:
            Dict[str, Any]: Detailed breakdown
        """
        breakdown = {
            "total_findings": len(findings),
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "category_counts": {},
            "deductions": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        }

        # Count findings by severity
        for finding in findings:
            severity = finding.severity
            if severity in breakdown["severity_counts"]:
                breakdown["severity_counts"][severity] += 1

            # Track deductions
            deduction = self.SEVERITY_WEIGHTS.get(severity, 1)
            breakdown["deductions"][severity] += deduction * finding.confidence

            # Count by category
            category = finding.category
            if category not in breakdown["category_counts"]:
                breakdown["category_counts"][category] = 0
            breakdown["category_counts"][category] += 1

        return breakdown

    def _calculate_factors(
        self,
        findings: List[Finding]
    ) -> Dict[str, Any]:
        """
        Calculate factors that influenced the score.

        Args:
            findings: List of findings

        Returns:
            Dict[str, Any]: Score factors
        """
        factors = {
            "has_critical_findings": False,
            "has_high_findings": False,
            "has_medium_findings": False,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "total_findings": len(findings),
            "top_categories": [],
        }

        # Check for severity levels
        for finding in findings:
            severity = finding.severity
            if severity == "critical":
                factors["has_critical_findings"] = True
                factors["critical_count"] += 1
            elif severity == "high":
                factors["has_high_findings"] = True
                factors["high_count"] += 1
            elif severity == "medium":
                factors["has_medium_findings"] = True
                factors["medium_count"] += 1

        return factors

    def _calculate_grade(self, score: int) -> str:
        """
        Calculate letter grade based on score.

        Args:
            score: The security score

        Returns:
            str: Letter grade (A, B, C, D, F)
        """
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

    def _get_previous_score(self, website_id: UUID) -> Optional[int]:
        """
        Get the previous security score for a website.

        Args:
            website_id: ID of the website

        Returns:
            Optional[int]: Previous score or None
        """
        previous = self.db.query(SecurityScore).filter(
            SecurityScore.website_id == website_id
        ).order_by(
            SecurityScore.created_at.desc()
        ).first()

        return previous.overall_score if previous else None

    # ================================================================
    # Score Retrieval
    # ================================================================

    def get_score(self, scan_id: UUID) -> Optional[SecurityScore]:
        """
        Get the security score for a scan.

        Args:
            scan_id: ID of the scan

        Returns:
            Optional[SecurityScore]: The security score or None
        """
        return self.db.query(SecurityScore).filter(
            SecurityScore.scan_id == scan_id
        ).first()

    def get_latest_score(self, website_id: UUID) -> Optional[SecurityScore]:
        """
        Get the latest security score for a website.

        Args:
            website_id: ID of the website

        Returns:
            Optional[SecurityScore]: The latest score or None
        """
        return self.db.query(SecurityScore).filter(
            SecurityScore.website_id == website_id
        ).order_by(
            SecurityScore.created_at.desc()
        ).first()

    def get_score_history(
        self,
        website_id: UUID,
        limit: int = 10
    ) -> List[SecurityScore]:
        """
        Get score history for a website.

        Args:
            website_id: ID of the website
            limit: Maximum number of scores to return

        Returns:
            List[SecurityScore]: List of historical scores
        """
        return self.db.query(SecurityScore).filter(
            SecurityScore.website_id == website_id
        ).order_by(
            SecurityScore.created_at.desc()
        ).limit(limit).all()

    def get_website_score_summary(self, website_id: UUID) -> Dict[str, Any]:
        """
        Get a summary of security scores for a website.

        Args:
            website_id: ID of the website

        Returns:
            Dict[str, Any]: Score summary
        """
        website = self.db.query(Website).filter(
            Website.id == website_id
        ).first()

        if not website:
            return {}

        latest = self.get_latest_score(website_id)
        history = self.get_score_history(website_id, limit=5)

        # Calculate trend
        trend = "stable"
        if len(history) >= 2:
            if history[0].overall_score > history[1].overall_score:
                trend = "improving"
            elif history[0].overall_score < history[1].overall_score:
                trend = "declining"

        return {
            "website_id": str(website_id),
            "domain": website.domain,
            "latest_score": latest.overall_score if latest else None,
            "latest_grade": latest.grade if latest else None,
            "latest_scan_id": str(latest.scan_id) if latest else None,
            "trend": trend,
            "history": [
                {
                    "score": s.overall_score,
                    "grade": s.grade,
                    "date": s.created_at.isoformat(),
                    "scan_id": str(s.scan_id),
                }
                for s in history[:5]
            ],
            "total_scans": self.db.query(Scan).filter(
                Scan.website_id == website_id,
                Scan.status == "completed"
            ).count(),
        }

    # ================================================================
    # Score Statistics
    # ================================================================

    def get_user_score_stats(self, user_id: UUID) -> Dict[str, Any]:
        """
        Get score statistics for a user's websites.

        Args:
            user_id: ID of the user

        Returns:
            Dict[str, Any]: Score statistics
        """
        # Get all websites for the user
        websites = self.db.query(Website).filter(
            Website.user_id == user_id,
            Website.deleted_at.is_(None)
        ).all()

        if not websites:
            return {
                "total_websites": 0,
                "average_score": None,
                "highest_score": None,
                "lowest_score": None,
                "score_distribution": {},
            }

        scores = []
        for website in websites:
            latest = self.get_latest_score(website.id)
            if latest:
                scores.append(latest.overall_score)

        if not scores:
            return {
                "total_websites": len(websites),
                "average_score": None,
                "highest_score": None,
                "lowest_score": None,
                "score_distribution": {},
            }

        # Calculate distribution
        distribution = {
            "excellent": 0,  # 90-100
            "good": 0,       # 75-89
            "fair": 0,       # 50-74
            "poor": 0,       # 30-49
            "critical": 0,   # 0-29
        }

        for score in scores:
            if score >= 90:
                distribution["excellent"] += 1
            elif score >= 75:
                distribution["good"] += 1
            elif score >= 50:
                distribution["fair"] += 1
            elif score >= 30:
                distribution["poor"] += 1
            else:
                distribution["critical"] += 1

        return {
            "total_websites": len(websites),
            "scored_websites": len(scores),
            "average_score": sum(scores) / len(scores),
            "highest_score": max(scores),
            "lowest_score": min(scores),
            "score_distribution": distribution,
        }

    def get_category_score_breakdown(self, scan_id: UUID) -> Dict[str, Any]:
        """
        Get category score breakdown for a scan.

        Args:
            scan_id: ID of the scan

        Returns:
            Dict[str, Any]: Category breakdown
        """
        score = self.get_score(scan_id)

        if not score:
            return {}

        return {
            "scan_id": str(scan_id),
            "overall_score": score.overall_score,
            "grade": score.grade,
            "categories": score.category_scores or {},
            "weightings": score.weightings or {},
            "breakdown": score.breakdown or {},
        }

    def calculate_score_improvement(
        self,
        scan_id: UUID,
        previous_scan_id: UUID
    ) -> Dict[str, Any]:
        """
        Calculate score improvement between two scans.

        Args:
            scan_id: ID of the current scan
            previous_scan_id: ID of the previous scan

        Returns:
            Dict[str, Any]: Improvement analysis
        """
        current = self.get_score(scan_id)
        previous = self.get_score(previous_scan_id)

        if not current or not previous:
            return {
                "error": "One or both scans not found or not scored"
            }

        improvement = current.overall_score - previous.overall_score

        return {
            "current_score": current.overall_score,
            "previous_score": previous.overall_score,
            "improvement": improvement,
            "improvement_percentage": (improvement / previous.overall_score) * 100 if previous.overall_score > 0 else 0,
            "direction": "improved" if improvement > 0 else "declined" if improvement < 0 else "unchanged",
            "current_grade": current.grade,
            "previous_grade": previous.grade,
        }