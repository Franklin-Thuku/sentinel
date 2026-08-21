"""
Security Score model for Sentinel.

This model stores detailed security score calculations and breakdowns
for each scan. It provides transparency into how scores are calculated.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Integer,
    Float,
    Text,
    Index,
    func,
    ForeignKey,
    JSON,
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


class SecurityScore(Base):
    """
    Security Score model.

    Stores detailed security score calculations for scans.

    Attributes:
        id: Unique UUID identifier
        scan_id: ID of the scan this score belongs to
        website_id: ID of the website (denormalized for faster queries)
        overall_score: Overall security score (0-100)
        category_scores: JSON object with category-specific scores
        score_factors: JSON object with factors that influenced the score
        methodology_version: Version of the scoring methodology used
        grade: Letter grade (A, B, C, D, F)
        percentile: Percentile rank (if applicable)
        previous_score: Previous score for comparison
        score_change: Change from previous score
        max_score: Maximum possible score
        weightings: JSON object with category weightings used
        breakdown: Detailed breakdown of the score calculation
        metadata: Additional metadata as JSON
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "security_scores"

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
        unique=True,  # One score per scan
        index=True,
    )

    website_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ================================================================
    # Score Information
    # ================================================================

    overall_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    grade: Mapped[str] = mapped_column(
        String(2),
        nullable=False,
    )

    # ================================================================
    # Detailed Scores
    # ================================================================

    category_scores: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    score_factors: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    weightings: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    breakdown: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    # ================================================================
    # Methodology & Comparison
    # ================================================================

    methodology_version: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="1.0",
        server_default="1.0",
    )

    percentile: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )

    previous_score: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    score_change: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    max_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=100,
        server_default="100",
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
        Index("ix_security_scores_scan_id", "scan_id"),
        Index("ix_security_scores_website_score", "website_id", "overall_score"),
        Index("ix_security_scores_overall_score", "overall_score"),
        Index("ix_security_scores_grade", "grade"),
        Index("ix_security_scores_created_at", "created_at"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="security_scores",
        lazy="selectin",
    )

    website: Mapped["Website"] = relationship(
        "Website",
        back_populates="security_scores",
        lazy="selectin",
    )

    # ================================================================
    # Properties
    # ================================================================

    @property
    def is_excellent(self) -> bool:
        """Check if score is excellent."""
        return self.overall_score >= 90

    @property
    def is_good(self) -> bool:
        """Check if score is good."""
        return 75 <= self.overall_score < 90

    @property
    def is_fair(self) -> bool:
        """Check if score is fair."""
        return 50 <= self.overall_score < 75

    @property
    def is_poor(self) -> bool:
        """Check if score is poor."""
        return 30 <= self.overall_score < 50

    @property
    def is_critical(self) -> bool:
        """Check if score is critical."""
        return self.overall_score < 30

    @property
    def has_improved(self) -> bool:
        """Check if score improved from previous."""
        if self.previous_score is None:
            return False
        return self.overall_score > self.previous_score

    @property
    def has_declined(self) -> bool:
        """Check if score declined from previous."""
        if self.previous_score is None:
            return False
        return self.overall_score < self.previous_score

    @property
    def score_category(self) -> str:
        """Get the score category."""
        if self.is_excellent:
            return "Excellent"
        elif self.is_good:
            return "Good"
        elif self.is_fair:
            return "Fair"
        elif self.is_poor:
            return "Poor"
        else:
            return "Critical"

    @property
    def score_percentage(self) -> float:
        """Get score as percentage of max."""
        if self.max_score > 0:
            return (self.overall_score / self.max_score) * 100
        return 0.0

    # ================================================================
    # Helper Methods
    # ================================================================

    def calculate_grade(self) -> str:
        """Calculate grade based on score."""
        if self.overall_score >= 90:
            return "A"
        elif self.overall_score >= 75:
            return "B"
        elif self.overall_score >= 50:
            return "C"
        elif self.overall_score >= 30:
            return "D"
        else:
            return "F"

    def set_category_scores(self, categories: dict) -> None:
        """
        Set category scores.

        Args:
            categories: Dictionary with category names as keys and scores as values.
        """
        self.category_scores = categories

    def set_score_factors(self, factors: dict) -> None:
        """
        Set score factors.

        Args:
            factors: Dictionary with factors that influenced the score.
        """
        self.score_factors = factors

    def set_weightings(self, weightings: dict) -> None:
        """
        Set category weightings.

        Args:
            weightings: Dictionary with category names as keys and weights as values.
        """
        self.weightings = weightings

    def set_breakdown(self, breakdown: dict) -> None:
        """
        Set score breakdown.

        Args:
            breakdown: Dictionary with detailed score breakdown.
        """
        self.breakdown = breakdown

    def compare_with_previous(self, previous: "SecurityScore") -> None:
        """
        Compare with a previous score.

        Args:
            previous: Previous SecurityScore instance.
        """
        self.previous_score = previous.overall_score
        self.score_change = self.overall_score - previous.overall_score

    def get_category_score(self, category: str) -> Optional[int]:
        """
        Get score for a specific category.

        Args:
            category: Category name.

        Returns:
            Optional[int]: Score for the category, or None if not found.
        """
        if self.category_scores:
            return self.category_scores.get(category)
        return None

    def get_top_contributing_factors(self, limit: int = 5) -> list:
        """
        Get top contributing factors.

        Args:
            limit: Maximum number of factors to return.

        Returns:
            list: List of top contributing factors.
        """
        if not self.score_factors:
            return []
        # Sort by impact and return top N
        sorted_factors = sorted(
            self.score_factors.items(),
            key=lambda x: abs(x[1]) if isinstance(x[1], (int, float)) else 0,
            reverse=True
        )
        return sorted_factors[:limit]

    def get_summary(self) -> dict:
        """
        Get a summary of the score.

        Returns:
            dict: Summary of the score.
        """
        return {
            "overall_score": self.overall_score,
            "grade": self.grade,
            "category": self.score_category,
            "max_score": self.max_score,
            "score_percentage": self.score_percentage,
            "previous_score": self.previous_score,
            "score_change": self.score_change,
            "has_improved": self.has_improved,
            "has_declined": self.has_declined,
            "methodology_version": self.methodology_version,
        }

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<SecurityScore(id={self.id}, scan_id={self.scan_id}, "
            f"score={self.overall_score}, grade={self.grade})>"
        )

    def __str__(self) -> str:
        return f"Score {self.overall_score}/100 ({self.grade}) for scan {self.scan_id}"