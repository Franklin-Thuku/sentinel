"""
Base Scanner class for Sentinel.

All scanners inherit from this base class, which defines the
common interface for scanning operations.

Each scanner implements specific security checks and returns
normalized findings that can be stored in the database.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from datetime import datetime
import httpx
import logging

from app.config import settings

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners.

    Each scanner implements a specific security check:
    - Headers, TLS, DNS, Cookies, etc.

    Attributes:
        target_url: The URL to scan
        timeout: Request timeout in seconds
        max_redirects: Maximum redirects to follow
        user_agent: User agent to use for requests
        findings: List of findings discovered by this scanner
    """

    def __init__(
        self,
        target_url: str,
        timeout: int = settings.SCAN_REQUEST_TIMEOUT,
        max_redirects: int = settings.SCAN_MAX_REDIRECTS,
    ):
        self.target_url = target_url
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = settings.SCAN_USER_AGENT
        self.findings: List[Dict[str, Any]] = []
        self._client: Optional[httpx.AsyncClient] = None

    @abstractmethod
    async def scan(self) -> List[Dict[str, Any]]:
        """
        Execute the scanner.

        Returns:
            List of findings discovered by this scanner.
        """
        pass

    @abstractmethod
    def get_scanner_name(self) -> str:
        """
        Get the name of the scanner.

        Returns:
            The scanner name (e.g., "security_headers").
        """
        pass

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create an HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=self.max_redirects,
                headers={"User-Agent": self.user_agent},
                verify=False,  # Allow self-signed certificates for scanning
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _create_finding(
        self,
        severity: str,
        title: str,
        description: str,
        evidence: Optional[str] = None,
        affected_url: Optional[str] = None,
        remediation: Optional[str] = None,
        confidence: float = 1.0,
        references: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a standardized finding dictionary.

        Args:
            severity: critical, high, medium, low, info
            title: Short title of the finding
            description: Detailed description
            evidence: Evidence supporting the finding
            affected_url: URL affected by the finding
            remediation: Remediation recommendation
            confidence: Confidence score (0.0 - 1.0)
            references: List of reference URLs
            metadata: Additional metadata

        Returns:
            Standardized finding dictionary.
        """
        return {
            "scanner": self.get_scanner_name(),
            "category": self.get_scanner_name(),
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
            "affected_url": affected_url or self.target_url,
            "remediation": remediation,
            "confidence": confidence,
            "references": references or [],
            "metadata": metadata or {},
            "scanner_module": self.get_scanner_name(),
            "created_at": datetime.utcnow().isoformat(),
        }

    def _add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding to the findings list."""
        self.findings.append(finding)
        logger.info(
            f"[{self.get_scanner_name()}] Found {finding['severity']} finding: "
            f"{finding['title']}"
        )

    def _log_debug(self, message: str) -> None:
        """Log a debug message with scanner context."""
        logger.debug(f"[{self.get_scanner_name()}] {message}")

    def _log_info(self, message: str) -> None:
        """Log an info message with scanner context."""
        logger.info(f"[{self.get_scanner_name()}] {message}")

    def _log_warning(self, message: str) -> None:
        """Log a warning message with scanner context."""
        logger.warning(f"[{self.get_scanner_name()}] {message}")

    def _log_error(self, message: str) -> None:
        """Log an error message with scanner context."""
        logger.error(f"[{self.get_scanner_name()}] {message}")