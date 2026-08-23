"""
Verification service for Sentinel.

Handles website ownership verification using multiple methods:
- DNS TXT records
- HTTP file upload
- Meta tags
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from uuid import UUID

import httpx
import dns.resolver
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.db.models.website import Website
from app.db.models.website_verification import WebsiteVerification
from app.db.models.audit_log import AuditLog
from app.schemas.website import WebsiteVerifyRequest


class VerificationService:
    """Service for website verification operations."""

    def __init__(self, db: Session):
        """
        Initialize the verification service.

        Args:
            db: Database session
        """
        self.db = db

    # ================================================================
    # Verification Creation
    # ================================================================

    def create_verification(
        self,
        website_id: UUID,
        user_id: UUID,
        method: str = "dns_txt",
    ) -> WebsiteVerification:
        """
        Create a new verification record for a website.

        Args:
            website_id: ID of the website to verify
            user_id: ID of the user (for authorization)
            method: Verification method (dns_txt, http_file, meta_tag)

        Returns:
            WebsiteVerification: The created verification record

        Raises:
            HTTPException: If website not found or already verified
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

        if website.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Website is already verified"
            )

        # Check if there's an existing pending verification
        existing = self.db.query(WebsiteVerification).filter(
            WebsiteVerification.website_id == website_id,
            WebsiteVerification.status.in_(["pending", "verified"]),
            WebsiteVerification.expires_at > datetime.utcnow()
        ).first()

        if existing:
            # Return existing if still valid
            if existing.status == "pending":
                return existing
            elif existing.status == "verified" and existing.is_valid():
                return existing

        # Generate verification token
        token = secrets.token_urlsafe(32)

        # Create verification record
        verification = WebsiteVerification(
            website_id=website_id,
            method=method,
            token=token,
            status="pending",
            attempts=0,
            expires_at=datetime.utcnow() + timedelta(days=7),
        )

        self.db.add(verification)
        self.db.commit()
        self.db.refresh(verification)

        # Log the creation
        self._log_audit_event(
            user_id=user_id,
            action="verification_create",
            resource_type="verification",
            resource_id=str(verification.id),
            details={
                "website_id": str(website_id),
                "method": method,
                "token": token[:8] + "...",  # Partial token for security
            },
        )

        return verification

    def get_verification(self, verification_id: UUID, user_id: UUID) -> Optional[WebsiteVerification]:
        """
        Get a verification record by ID.

        Args:
            verification_id: ID of the verification record
            user_id: ID of the user (for authorization)

        Returns:
            Optional[WebsiteVerification]: The verification record

        Raises:
            HTTPException: If verification not found
        """
        verification = self.db.query(WebsiteVerification).filter(
            WebsiteVerification.id == verification_id
        ).first()

        if not verification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Verification not found"
            )

        # Check authorization
        website = self.db.query(Website).filter(
            Website.id == verification.website_id,
            Website.user_id == user_id
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this verification"
            )

        return verification

    def get_verification_for_website(
        self,
        website_id: UUID,
        user_id: UUID,
    ) -> Optional[WebsiteVerification]:
        """
        Get the active verification for a website.

        Args:
            website_id: ID of the website
            user_id: ID of the user (for authorization)

        Returns:
            Optional[WebsiteVerification]: The verification record
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

        # Get the most recent pending/verified verification
        verification = self.db.query(WebsiteVerification).filter(
            WebsiteVerification.website_id == website_id,
            WebsiteVerification.status.in_(["pending", "verified"]),
            WebsiteVerification.expires_at > datetime.utcnow()
        ).order_by(WebsiteVerification.created_at.desc()).first()

        return verification

    # ================================================================
    # Verification Methods
    # ================================================================

    def get_verification_instructions(
        self,
        website_id: UUID,
        user_id: UUID,
    ) -> Dict[str, Any]:
        """
        Get verification instructions for a website.

        Args:
            website_id: ID of the website
            user_id: ID of the user

        Returns:
            Dict[str, Any]: Verification instructions
        """
        verification = self.get_verification_for_website(website_id, user_id)

        if not verification:
            verification = self.create_verification(website_id, user_id)

        website = self.db.query(Website).filter(
            Website.id == website_id
        ).first()

        instructions = verification.get_verification_instructions()

        return {
            "verification_id": str(verification.id),
            "method": verification.method,
            "token": verification.token,
            "domain": website.domain,
            "instructions": instructions,
            "expires_at": verification.expires_at.isoformat(),
            "status": verification.status,
        }

    async def verify_dns_txt(self, verification: WebsiteVerification) -> bool:
        """
        Verify ownership via DNS TXT record.

        Args:
            verification: The verification record

        Returns:
            bool: True if verification successful
        """
        website = self.db.query(Website).filter(
            Website.id == verification.website_id
        ).first()

        if not website:
            return False

        # DNS record name
        record_name = f"_sentinel-verification.{website.domain}"
        expected_value = f"sentinel-verification={verification.token}"

        try:
            # Query DNS TXT records
            answers = dns.resolver.resolve(record_name, "TXT")
            
            for answer in answers:
                # TXT records can return multiple strings joined together
                record_value = "".join(answer.strings).decode('utf-8')
                if record_value == expected_value:
                    return True

            return False

        except dns.resolver.NXDOMAIN:
            # Record doesn't exist
            return False
        except dns.resolver.NoAnswer:
            # No TXT records
            return False
        except dns.exception.Timeout:
            # DNS timeout
            return False
        except Exception as e:
            # Other errors
            return False

    async def verify_http_file(self, verification: WebsiteVerification) -> bool:
        """
        Verify ownership via HTTP file.

        Args:
            verification: The verification record

        Returns:
            bool: True if verification successful
        """
        website = self.db.query(Website).filter(
            Website.id == verification.website_id
        ).first()

        if not website:
            return False

        # File URL
        file_url = f"https://{website.domain}/.well-known/sentinel-verification.txt"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(file_url)
                
                if response.status_code == 200:
                    content = response.text.strip()
                    return content == verification.token

                return False

        except httpx.RequestError:
            return False
        except Exception:
            return False

    async def verify_meta_tag(self, verification: WebsiteVerification) -> bool:
        """
        Verify ownership via HTML meta tag.

        Args:
            verification: The verification record

        Returns:
            bool: True if verification successful
        """
        website = self.db.query(Website).filter(
            Website.id == verification.website_id
        ).first()

        if not website:
            return False

        # Website URL
        url = f"https://{website.domain}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
                
                if response.status_code == 200:
                    html = response.text
                    # Look for meta tag
                    meta_tag = f'<meta name="sentinel-verification" content="{verification.token}"'
                    return meta_tag in html

                return False

        except httpx.RequestError:
            return False
        except Exception:
            return False

    # ================================================================
    # Verification Processing
    # ================================================================

    async def verify_website(
        self,
        website_id: UUID,
        user_id: UUID,
        request: Optional[WebsiteVerifyRequest] = None,
    ) -> Dict[str, Any]:
        """
        Verify a website using the specified method.

        Args:
            website_id: ID of the website
            user_id: ID of the user
            request: Optional verification request with method

        Returns:
            Dict[str, Any]: Verification result

        Raises:
            HTTPException: If verification fails
        """
        # Get verification record
        verification = self.get_verification_for_website(website_id, user_id)

        if not verification:
            verification = self.create_verification(
                website_id,
                user_id,
                method=request.method if request else "dns_txt",
            )

        if verification.is_verified and verification.is_valid():
            return {
                "verified": True,
                "message": "Website is already verified",
                "verification_id": str(verification.id),
            }

        # Increment attempts
        verification.increment_attempts()
        self.db.commit()

        # Run verification based on method
        method = verification.method
        verified = False

        if method == "dns_txt":
            verified = await self.verify_dns_txt(verification)
        elif method == "http_file":
            verified = await self.verify_http_file(verification)
        elif method == "meta_tag":
            verified = await self.verify_meta_tag(verification)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported verification method: {method}"
            )

        # Update verification status
        if verified:
            verification.mark_verified()
            
            # Update website
            website = self.db.query(Website).filter(
                Website.id == website_id
            ).first()
            if website:
                website.is_verified = True
                website.mark_verified()

            self.db.commit()

            # Log success
            self._log_audit_event(
                user_id=user_id,
                action="verification_success",
                resource_type="verification",
                resource_id=str(verification.id),
                details={
                    "website_id": str(website_id),
                    "method": method,
                },
            )

            return {
                "verified": True,
                "message": "Website verified successfully!",
                "verification_id": str(verification.id),
                "method": method,
            }
        else:
            # Check if should mark as failed
            if verification.attempts >= 3:
                verification.mark_failed("Verification failed after 3 attempts")
                self.db.commit()

            return {
                "verified": False,
                "message": f"Verification failed. Please check your {method} configuration.",
                "verification_id": str(verification.id),
                "method": method,
                "attempts": verification.attempts,
                "instructions": verification.get_verification_instructions(),
            }

    # ================================================================
    # Verification Management
    # ================================================================

    def refresh_verification(self, verification_id: UUID, user_id: UUID) -> WebsiteVerification:
        """
        Refresh a verification token.

        Args:
            verification_id: ID of the verification record
            user_id: ID of the user

        Returns:
            WebsiteVerification: The refreshed verification record

        Raises:
            HTTPException: If verification not found or already verified
        """
        verification = self.get_verification(verification_id, user_id)

        if verification.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot refresh an already verified verification"
            )

        # Reset verification
        verification.reset()
        self.db.commit()
        self.db.refresh(verification)

        return verification

    def delete_verification(self, verification_id: UUID, user_id: UUID) -> None:
        """
        Delete a verification record.

        Args:
            verification_id: ID of the verification record
            user_id: ID of the user

        Raises:
            HTTPException: If verification not found
        """
        verification = self.get_verification(verification_id, user_id)

        # If website is verified, don't allow deletion
        website = self.db.query(Website).filter(
            Website.id == verification.website_id
        ).first()

        if website and website.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete verification for a verified website"
            )

        self.db.delete(verification)
        self.db.commit()

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