"""
Website Verification model for Sentinel.

This model tracks ownership verification attempts for websites.
Verification is required before a website can be scanned.
"""

import uuid
from datetime import datetime, timedelta  # ← FIXED: timedelta imported here
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String,
    DateTime,
    Text,
    Enum,
    Index,
    func,
    Integer,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# ================================================================
# TYPE_CHECKING: Avoid circular import errors
# ================================================================

if TYPE_CHECKING:
    from app.db.models.website import Website


class WebsiteVerification(Base):
    """
    Website Verification model.

    Tracks verification attempts for website ownership.
    Supports multiple verification methods.

    Attributes:
        id: Unique UUID identifier
        website_id: ID of the website being verified
        method: Verification method (dns, http_file, meta_tag, email)
        token: Unique verification token
        status: Verification status (pending, verified, failed, expired)
        attempts: Number of verification attempts
        last_attempt_at: Timestamp of the last attempt
        verified_at: Timestamp when verification succeeded
        expires_at: Timestamp when verification expires
        error_message: Error message if verification failed
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "website_verifications"

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

    website_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ================================================================
    # Verification Information
    # ================================================================

    method: Mapped[str] = mapped_column(
        Enum("dns_txt", "http_file", "meta_tag", name="verification_method"),
        nullable=False,
    )

    token: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    # ================================================================
    # Status
    # ================================================================

    status: Mapped[str] = mapped_column(
        Enum("pending", "verified", "failed", "expired", name="verification_status"),
        nullable=False,
        default="pending",
        server_default="pending",
    )

    attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    # ================================================================
    # Timestamps
    # ================================================================

    last_attempt_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # ================================================================
    # Error Information
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
        Index("ix_website_verifications_status", "status"),
        Index("ix_website_verifications_expires_at", "expires_at"),
        Index("ix_website_verifications_website_status", "website_id", "status"),
        Index("ix_website_verifications_token", "token"),
    )

    # ================================================================
    # Relationships
    # ================================================================

    website: Mapped["Website"] = relationship(
        "Website",
        back_populates="verifications",
        lazy="selectin",
    )

    # ================================================================
    # Helper Methods
    # ================================================================

    def is_valid(self) -> bool:
        """Check if verification is still valid."""
        return (
            self.status == "verified"
            and self.verified_at is not None
            and datetime.utcnow() < self.expires_at
        )

    def is_expired(self) -> bool:
        """Check if verification has expired."""
        return datetime.utcnow() > self.expires_at

    def mark_verified(self) -> None:
        """Mark verification as successful."""
        self.status = "verified"
        self.verified_at = datetime.utcnow()
        # Set expiry to 30 days from now by default
        self.expires_at = datetime.utcnow() + timedelta(days=30)

    def mark_failed(self, error: str) -> None:
        """Mark verification as failed."""
        self.status = "failed"
        self.error_message = error
        self.last_attempt_at = datetime.utcnow()
        self.attempts += 1

    def mark_expired(self) -> None:
        """Mark verification as expired."""
        self.status = "expired"

    def increment_attempts(self) -> int:
        """Increment attempts counter and return new count."""
        self.attempts += 1
        self.last_attempt_at = datetime.utcnow()
        return self.attempts

    def reset(self) -> None:
        """Reset verification to pending state."""
        self.status = "pending"
        self.attempts = 0
        self.last_attempt_at = None
        self.verified_at = None
        self.error_message = None
        # Set expiry to 7 days from now
        self.expires_at = datetime.utcnow() + timedelta(days=7)

    def get_verification_instructions(self) -> dict:
        """
        Get instructions for the verification method.

        Returns:
            dict: Instructions based on the verification method.
        """
        instructions = {
            "dns_txt": {
                "type": "DNS TXT Record",
                "domain": self.website.domain,
                "record": f"_sentinel-verification.{self.website.domain}",
                "value": f"sentinel-verification={self.token}",
                "instructions": (
                    f"Add a TXT record for `_sentinel-verification.{self.website.domain}` "
                    f"with the value `sentinel-verification={self.token}`"
                ),
            },
            "http_file": {
                "type": "HTTP File",
                "url": f"https://{self.website.domain}/.well-known/sentinel-verification.txt",
                "content": self.token,
                "instructions": (
                    f"Create a file at `/.well-known/sentinel-verification.txt` "
                    f"containing the text: {self.token}"
                ),
            },
            "meta_tag": {
                "type": "HTML Meta Tag",
                "tag": f'<meta name="sentinel-verification" content="{self.token}" />',
                "instructions": (
                    f"Add this meta tag to the `<head>` section of your website: "
                    f'<meta name="sentinel-verification" content="{self.token}" />'
                ),
            },
        }
        return instructions.get(self.method, {})

    # ================================================================
    # String Representation
    # ================================================================

    def __repr__(self) -> str:
        return (
            f"<WebsiteVerification(id={self.id}, website_id={self.website_id}, "
            f"method={self.method}, status={self.status})>"
        )

    def __str__(self) -> str:
        return f"{self.method} verification for {self.website_id} - {self.status}"