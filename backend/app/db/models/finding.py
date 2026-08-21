"""
Finding model for Sentinel.

This model represents individual security findings discovered during scans.
Each finding is a specific vulnerability, misconfiguration, or security issue.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Text,
    Enum,
    Index,
    func,
    ForeignKey,
    JSON,
    Float,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# ================================================================
# TYPE_CHECKING: Avoid circular import errors
# ================================================================

if TYPE_CHECKING:
    from app.db.models.scan import Scan
    from app.db.models.website import Website
    from app.db.models.ai_analysis import AIAnalysis


class Finding(Base):
    """
    Finding model.

    Represents a single security finding discovered during a scan.

    Attributes:
        id: Unique UUID identifier
        scan_id: ID of the scan that discovered this finding
        website_id: ID of the website affected
        category: Finding category (headers, tls, dns, cookies, etc.)
        severity: Severity level (critical, high, medium, low, info)
        title: Short title of the finding
        description: Detailed description
        evidence: Evidence supporting the finding
        affected_url: Specific URL affected (if applicable)
        confidence: Confidence score (0.0 - 1.0)
        remediation: Remediation recommendation
        technical_remediation: Technical steps to fix
        business_impact: Business impact explanation
        references: References (CVE, OWASP, etc.)
        status: Finding status (open, acknowledged, resolved, false_positive)
        cwe_id: CWE ID if applicable
        cvss_score: CVSS score if applicable
        cvss_vector: CVSS vector string
        scanner_module: Which scanner module found this
        metadata: Additional metadata as JSON
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "findings"

    # ================================================================
    # Primary Key
    # ================================================================

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # ================================================================
    # Foreign Keys
    # ================================================================

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    website_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ================================================================
    # Finding Information
    # ================================================================

    category: Mapped[str] = mapped_column(
        Enum(
            "headers",
            "tls",
            "dns",
            "cookies",
            "content",
            "robots",
            "sitemap",
            "technology",
            "passive",
            "configuration",
            "server",
            "ssl",
            "csrf",
            "xss",
            "sql_injection",
            "open_redirect",
            "information_disclosure",
            "misconfiguration",
            "other",
            name="finding_category"
        ),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        Enum(
            "critical",
            "high",
            "medium",
            "low",
            "info",
            name="finding_severity"
        ),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # ================================================================
    # Evidence & Affected
    # ================================================================

    evidence: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    affected_url: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    # ================================================================
    # Confidence & Scoring
    # ================================================================

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=1.0,
        server_default="1.0",
    )

    cwe_id: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
        index=True,
    )

    cvss_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )

    cvss_vector: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    # ================================================================
    # Remediation
    # ================================================================

    remediation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    technical_remediation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    business_impact: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # ================================================================
    # References
    # ================================================================

    references: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
    )

    # ================================================================
    # Status
    # ================================================================

    status: Mapped[str] = mapped_column(
        Enum(
            "open",
            "acknowledged",
            "resolved",
            "false_positive",
            "wont_fix",
            "duplicate",
            name="finding_status"
        ),
        nullable=False,
        default="open",
        server_default="open",
        index=True,
    )

    # ================================================================
    # Scanner Information
    # ================================================================

    scanner_module: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    # ================================================================
    # Metadata
    # ================================================================

    additional_metadata: Mapped[Optional[dict]] = mapped_column(
        "metadata",
        JSON,
        nullable=True,
    )

    # ================================================================
    # Timestamps
    # ================================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # ================================================================
    # Indexes
    # ================================================================

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_website_severity", "website_id", "severity"),
        Index("ix_findings_category", "category"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_created_at", "created_at"),
        Index("ix_findings_cwe_id", "cwe_id"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="findings",
        lazy="selectin",
    )

    website: Mapped["Website"] = relationship(
        "Website",
        back_populates="findings",
        lazy="selectin",
    )

    ai_analysis: Mapped[Optional["AIAnalysis"]] = relationship(
        "AIAnalysis",
        back_populates="finding",
        lazy="selectin",
        cascade="all, delete-orphan",
        uselist=False,
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def is_critical(self) -> bool:
        """Check if finding is critical severity."""
        return self.severity == "critical"

    @property
    def is_high(self) -> bool:
        """Check if finding is high severity."""
        return self.severity == "high"

    @property
    def is_medium(self) -> bool:
        """Check if finding is medium severity."""
        return self.severity == "medium"

    @property
    def is_low(self) -> bool:
        """Check if finding is low severity."""
        return self.severity == "low"

    @property
    def is_info(self) -> bool:
        """Check if finding is informational."""
        return self.severity == "info"

    @property
    def is_open(self) -> bool:
        """Check if finding is still open."""
        return self.status == "open"

    @property
    def is_resolved(self) -> bool:
        """Check if finding is resolved."""
        return self.status in ("resolved", "false_positive", "wont_fix", "duplicate")

    @property
    def severity_score(self) -> int:
        """Get numeric severity score for sorting."""
        return {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }.get(self.severity, 0)

    @property
    def severity_color(self) -> str:
        """Get severity color for UI."""
        return {
            "critical": "red-600",
            "high": "orange-500",
            "medium": "yellow-500",
            "low": "blue-400",
            "info": "gray-400",
        }.get(self.severity, "gray-400")

    @property
    def severity_icon(self) -> str:
        """Get severity icon for UI."""
        return {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "ℹ️",
        }.get(self.severity, "⚪")

    # ================================================================
    # Helper Methods
    # ================================================================

    def acknowledge(self) -> None:
        """Acknowledge the finding."""
        self.status = "acknowledged"

    def resolve(self) -> None:
        """Mark finding as resolved."""
        self.status = "resolved"

    def mark_false_positive(self) -> None:
        """Mark finding as false positive."""
        self.status = "false_positive"

    def mark_wont_fix(self) -> None:
        """Mark finding as won't fix."""
        self.status = "wont_fix"

    def mark_duplicate(self) -> None:
        """Mark finding as duplicate."""
        self.status = "duplicate"

    def reopen(self) -> None:
        """Reopen a resolved finding."""
        self.status = "open"

    def has_ai_analysis(self) -> bool:
        """Check if finding has AI analysis."""
        return self.ai_analysis is not None

    def get_display_severity(self) -> str:
        """Get formatted severity string."""
        return self.severity.upper()

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<Finding(id={self.id}, scan_id={self.scan_id}, "
            f"severity={self.severity}, title={self.title[:50]})>"
        )

    def __str__(self) -> str:
        return f"{self.severity.upper()}: {self.title[:50]}"