"""
AI Analysis model for Sentinel.

This model stores AI-generated explanations and remediation guidance
for security findings. Each finding can have one AI analysis.
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
    Integer,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# ================================================================
# TYPE_CHECKING: Avoid circular import errors
# ================================================================

if TYPE_CHECKING:
    from app.db.models.finding import Finding
    from app.db.models.scan import Scan


class AIAnalysis(Base):
    """
    AI Analysis model.

    Stores AI-generated explanations and remediation guidance
    for security findings.

    Attributes:
        id: Unique UUID identifier
        finding_id: ID of the finding being analyzed
        scan_id: ID of the scan (denormalized for faster queries)
        status: Analysis status (pending, processing, completed, failed)
        provider: AI provider used (openai, anthropic, mock)
        model: Model used for analysis
        input_tokens: Number of input tokens used
        output_tokens: Number of output tokens used
        plain_explanation: Plain-English explanation for non-technical users
        risk_explanation: Risk explanation
        technical_explanation: Technical explanation for developers
        recommended_remediation: Remediation steps
        developer_remediation: Developer-specific remediation
        business_impact: Business impact explanation
        priority: AI-assigned priority (critical, high, medium, low)
        confidence: AI confidence in analysis (0.0 - 1.0)
        references: References used in analysis
        metadata: Additional metadata as JSON
        error_message: Error if analysis failed
        created_at: Creation timestamp
        updated_at: Last update timestamp
        completed_at: Completion timestamp
    """

    __tablename__ = "ai_analyses"

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

    finding_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # One-to-one relationship
        index=True,
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ================================================================
    # Status & Provider
    # ================================================================

    status: Mapped[str] = mapped_column(
        Enum(
            "pending",
            "processing",
            "completed",
            "failed",
            name="ai_analysis_status"
        ),
        nullable=False,
        default="pending",
        server_default="pending",
        index=True,
    )

    provider: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    model: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    # ================================================================
    # Token Usage
    # ================================================================

    input_tokens: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    output_tokens: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    # ================================================================
    # Analysis Content
    # ================================================================

    plain_explanation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    risk_explanation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    technical_explanation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    recommended_remediation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    developer_remediation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    business_impact: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    priority: Mapped[Optional[str]] = mapped_column(
        Enum(
            "critical",
            "high",
            "medium",
            "low",
            name="ai_priority"
        ),
        nullable=True,
    )

    confidence: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )

    # ================================================================
    # References & Metadata
    # ================================================================

    references: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
    )

    additional_metadata: Mapped[Optional[dict]] = mapped_column(
        "metadata",
        JSON,
        nullable=True,
    )

    # ================================================================
    # Error Handling
    # ================================================================

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
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

    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ================================================================
    # Indexes
    # ================================================================

    __table_args__ = (
        Index("ix_ai_analyses_finding_id", "finding_id"),
        Index("ix_ai_analyses_scan_id", "scan_id"),
        Index("ix_ai_analyses_status", "status"),
        Index("ix_ai_analyses_created_at", "created_at"),
        Index("ix_ai_analyses_priority", "priority"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    finding: Mapped["Finding"] = relationship(
        "Finding",
        back_populates="ai_analysis",
        lazy="selectin",
    )

    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="ai_analyses",
        lazy="selectin",
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def is_completed(self) -> bool:
        """Check if analysis is completed."""
        return self.status == "completed"

    @property
    def is_failed(self) -> bool:
        """Check if analysis failed."""
        return self.status == "failed"

    @property
    def is_processing(self) -> bool:
        """Check if analysis is processing."""
        return self.status == "processing"

    @property
    def is_pending(self) -> bool:
        """Check if analysis is pending."""
        return self.status == "pending"

    @property
    def total_tokens(self) -> Optional[int]:
        """Get total tokens used."""
        if self.input_tokens is not None and self.output_tokens is not None:
            return self.input_tokens + self.output_tokens
        return None

    @property
    def priority_display(self) -> str:
        """Get formatted priority string."""
        if self.priority:
            return self.priority.upper()
        return "UNKNOWN"

    @property
    def has_full_analysis(self) -> bool:
        """Check if all analysis fields are populated."""
        return all([
            self.plain_explanation,
            self.risk_explanation,
            self.technical_explanation,
            self.recommended_remediation,
            self.developer_remediation,
            self.business_impact,
        ])

    # ================================================================
    # Helper Methods
    # ================================================================

    def mark_processing(self) -> None:
        """Mark analysis as processing."""
        self.status = "processing"

    def mark_completed(self) -> None:
        """Mark analysis as completed."""
        self.status = "completed"
        self.completed_at = datetime.utcnow()

    def mark_failed(self, error: str) -> None:
        """Mark analysis as failed."""
        self.status = "failed"
        self.error_message = error
        self.completed_at = datetime.utcnow()

    def set_analysis(self, data: dict) -> None:
        """
        Set analysis data from a dictionary.

        Args:
            data: Dictionary containing analysis data.
        """
        self.plain_explanation = data.get("plain_explanation")
        self.risk_explanation = data.get("risk_explanation")
        self.technical_explanation = data.get("technical_explanation")
        self.recommended_remediation = data.get("recommended_remediation")
        self.developer_remediation = data.get("developer_remediation")
        self.business_impact = data.get("business_impact")
        self.priority = data.get("priority")
        self.confidence = data.get("confidence")
        self.references = data.get("references")

    def set_provider_info(self, provider: str, model: str, tokens: dict) -> None:
        """Set provider information and token usage."""
        self.provider = provider
        self.model = model
        self.input_tokens = tokens.get("input_tokens")
        self.output_tokens = tokens.get("output_tokens")

    def get_summary(self) -> dict:
        """
        Get a summary of the analysis.

        Returns:
            dict: Summary of the analysis.
        """
        return {
            "has_analysis": self.has_full_analysis,
            "status": self.status,
            "priority": self.priority,
            "confidence": self.confidence,
            "provider": self.provider,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
        }

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<AIAnalysis(id={self.id}, finding_id={self.finding_id}, "
            f"status={self.status}, provider={self.provider})>"
        )

    def __str__(self) -> str:
        return f"AI Analysis for finding {self.finding_id} - {self.status}"
