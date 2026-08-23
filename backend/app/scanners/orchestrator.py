"""
Scanner Orchestrator for Sentinel.

Orchestrates all scanners to perform a complete security scan.
Manages:
- Scanner execution order
- Parallel execution
- Result aggregation
- Scoring calculation
- Scan summary generation
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.scanners.base import BaseScanner
from app.scanners.http_scanner import HTTPScanner
from app.scanners.security_headers_scanner import SecurityHeadersScanner
from app.scanners.tls_scanner import TLSScanner
from app.scanners.dns_scanner import DNSScanner
from app.scanners.cookie_scanner import CookieScanner
from app.scanners.robots_scanner import RobotsScanner
from app.scanners.sitemap_scanner import SitemapScanner
from app.scanners.technology_scanner import TechnologyScanner
from app.scanners.passive_scanner import PassiveScanner

from app.config import settings


class ScannerOrchestrator:
    """
    Orchestrates all scanners for a complete security scan.

    Attributes:
        target_url: The URL to scan
        findings: All findings from all scanners
        scan_results: Aggregated scan results
        scan_type: Type of scan (full, quick, passive)
    """

    def __init__(self, target_url: str):
        """
        Initialize the orchestrator.

        Args:
            target_url: The URL to scan.
        """
        self.target_url = target_url
        self.findings: List[Dict[str, Any]] = []
        self.scan_results: Dict[str, Any] = {}
        self.scan_type = "full"
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    async def run_scan(self, scan_type: str = "full") -> Dict[str, Any]:
        """
        Run a complete security scan.

        Args:
            scan_type: Type of scan (full, quick, passive)

        Returns:
            Dict[str, Any]: Aggregated scan results.
        """
        self.start_time = datetime.utcnow()
        self.scan_type = scan_type

        # Select scanners based on scan type
        scanners = self._get_scanners()

        # Run scanners in parallel
        scan_tasks = [scanner.scan() for scanner in scanners]
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)

        # Collect findings
        for result in results:
            if isinstance(result, Exception):
                # Log error but continue
                print(f"Scanner error: {result}")
                continue
            if isinstance(result, list):
                self.findings.extend(result)

        # Calculate score
        score = self._calculate_score()

        # Generate summary
        summary = self._generate_summary()

        # Close all scanner clients
        for scanner in scanners:
            await scanner.close()

        self.end_time = datetime.utcnow()

        # Prepare results
        self.scan_results = {
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "started_at": self.start_time.isoformat(),
            "completed_at": self.end_time.isoformat(),
            "duration_seconds": (self.end_time - self.start_time).total_seconds(),
            "total_findings": len(self.findings),
            "score": score,
            "findings": self.findings,
            "summary": summary,
            "scanners_ran": [scanner.get_scanner_name() for scanner in scanners],
        }

        return self.scan_results

    def _get_scanners(self) -> List[BaseScanner]:
        """
        Get scanners based on scan type.

        Returns:
            List[BaseScanner]: List of scanners to run.
        """
        if self.scan_type == "quick":
            # Quick scan: only the most critical checks
            return [
                HTTPScanner(self.target_url),
                SecurityHeadersScanner(self.target_url),
                TLSScanner(self.target_url),
            ]

        elif self.scan_type == "passive":
            # Passive scan: only passive checks
            return [
                DNSScanner(self.target_url),
                PassiveScanner(self.target_url),
            ]

        else:
            # Full scan: all scanners
            return [
                HTTPScanner(self.target_url),
                SecurityHeadersScanner(self.target_url),
                TLSScanner(self.target_url),
                DNSScanner(self.target_url),
                CookieScanner(self.target_url),
                RobotsScanner(self.target_url),
                SitemapScanner(self.target_url),
                TechnologyScanner(self.target_url),
                PassiveScanner(self.target_url),
            ]

    def _calculate_score(self) -> Dict[str, Any]:
        """
        Calculate security score based on findings.

        Returns:
            Dict[str, Any]: Score information.
        """
        if not self.findings:
            return {
                "overall_score": 100,
                "grade": "A",
                "category_scores": {},
                "factors": {},
            }

        # Track deductions by severity
        deductions = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        # Track counts by severity
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        # Apply deductions
        for finding in self.findings:
            severity = finding.get("severity", "info")
            confidence = finding.get("confidence", 1.0)
            counts[severity] = counts.get(severity, 0) + 1

            # Severity weights
            weights = {
                "critical": 25,
                "high": 15,
                "medium": 8,
                "low": 3,
                "info": 1,
            }

            deduction = weights.get(severity, 1) * confidence
            deductions[severity] = deductions.get(severity, 0) + deduction

        # Calculate total deduction
        total_deduction = sum(deductions.values())

        # Calculate final score
        final_score = max(0, int(100 - total_deduction))

        # Calculate grade
        grade = self._calculate_grade(final_score)

        return {
            "overall_score": final_score,
            "grade": grade,
            "category_scores": {},
            "factors": {
                "critical_count": counts["critical"],
                "high_count": counts["high"],
                "medium_count": counts["medium"],
                "low_count": counts["low"],
                "info_count": counts["info"],
                "total_findings": len(self.findings),
                "has_critical": counts["critical"] > 0,
                "has_high": counts["high"] > 0,
            },
        }

    def _calculate_grade(self, score: int) -> str:
        """
        Calculate grade based on score.

        Args:
            score: The security score.

        Returns:
            str: Grade (A, B, C, D, F).
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

    def _generate_summary(self) -> Dict[str, Any]:
        """
        Generate a summary of the scan.

        Returns:
            Dict[str, Any]: Scan summary.
        """
        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in self.findings:
            severity = finding.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Count by scanner
        scanner_counts = {}
        for finding in self.findings:
            scanner = finding.get("scanner", "unknown")
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

        return {
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "scanner_counts": scanner_counts,
            "top_categories": self._get_top_categories(),
        }

    def _get_top_categories(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Get top findings by category.

        Args:
            limit: Number of categories to return.

        Returns:
            List[Dict[str, Any]]: Top categories.
        """
        category_counts = {}
        for finding in self.findings:
            category = finding.get("category", "other")
            category_counts[category] = category_counts.get(category, 0) + 1

        # Sort by count descending
        sorted_categories = sorted(
            category_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [
            {"category": cat, "count": count}
            for cat, count in sorted_categories[:limit]
        ]

    def get_results(self) -> Dict[str, Any]:
        """
        Get the scan results.

        Returns:
            Dict[str, Any]: Scan results.
        """
        return self.scan_results