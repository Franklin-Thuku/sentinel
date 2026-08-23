"""
Website service for Sentinel.

Handles website management: add, list, get, update, delete websites.
"""

import re
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.db.models.website import Website
from app.db.models.user import User
from app.db.models.organization import Organization
from app.schemas.website import WebsiteCreate, WebsiteUpdate, WebsiteResponse


class WebsiteService:
    """Service for website-related operations."""

    def __init__(self, db: Session):
        """
        Initialize the website service.

        Args:
            db: Database session
        """
        self.db = db

    # ================================================================
    # CRUD Operations
    # ================================================================

    def create_website(self, user_id: UUID, website_data: WebsiteCreate) -> Website:
        """
        Create a new website for a user.

        Args:
            user_id: ID of the user creating the website
            website_data: Website creation data

        Returns:
            Website: The created website

        Raises:
            HTTPException: If validation fails or website already exists
        """
        # Validate URL format
        self._validate_url(website_data.url)

        # Check if website already exists for this user (including deleted)
        existing = self.db.query(Website).filter(
            Website.user_id == user_id,
            Website.url == website_data.url
        ).first()

        if existing:
            # If soft-deleted, restore it
            if existing.deleted_at is not None:
                existing.restore()
                existing.name = website_data.name or existing.name
                existing.description = website_data.description
                existing.is_verified = False
                self.db.commit()
                self.db.refresh(existing)
                return existing
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Website already exists"
            )

        # Normalize URL
        normalized_url = self._normalize_url(website_data.url)

        # Create website
        website = Website(
            user_id=user_id,
            organization_id=website_data.organization_id,
            url=normalized_url,
            name=website_data.name or normalized_url,
            description=website_data.description,
            is_verified=False,
            is_active=True,
        )

        self.db.add(website)
        self.db.commit()
        self.db.refresh(website)

        return website

    def get_websites(
        self,
        user_id: UUID,
        organization_id: Optional[UUID] = None,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
    ) -> List[Website]:
        """
        Get websites for a user.

        Args:
            user_id: ID of the user
            organization_id: Optional filter by organization
            skip: Number of records to skip (pagination)
            limit: Maximum number of records to return
            search: Optional search term

        Returns:
            List[Website]: List of websites
        """
        query = self.db.query(Website).filter(
            Website.user_id == user_id,
            Website.deleted_at == None
        )

        if organization_id:
            query = query.filter(Website.organization_id == organization_id)

        if search:
            query = query.filter(
                or_(
                    Website.url.ilike(f"%{search}%"),
                    Website.name.ilike(f"%{search}%"),
                )
            )

        return query.order_by(Website.created_at.desc()).offset(skip).limit(limit).all()

    def get_website(self, website_id: UUID, user_id: UUID) -> Optional[Website]:
        """
        Get a specific website by ID.

        Args:
            website_id: ID of the website
            user_id: ID of the user (for authorization)

        Returns:
            Optional[Website]: The website if found and owned by the user

        Raises:
            HTTPException: If website not found or not owned by user
        """
        website = self.db.query(Website).filter(
            Website.id == website_id,
            Website.user_id == user_id,
            Website.deleted_at == None
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Website not found"
            )

        return website

    def update_website(
        self,
        website_id: UUID,
        user_id: UUID,
        update_data: WebsiteUpdate
    ) -> Website:
        """
        Update a website.

        Args:
            website_id: ID of the website
            user_id: ID of the user (for authorization)
            update_data: Update data

        Returns:
            Website: The updated website

        Raises:
            HTTPException: If website not found or not owned by user
        """
        website = self.get_website(website_id, user_id)

        # Update fields
        if update_data.name is not None:
            website.name = update_data.name

        if update_data.description is not None:
            website.description = update_data.description

        if update_data.url is not None:
            self._validate_url(update_data.url)
            website.url = self._normalize_url(update_data.url)

        if update_data.is_active is not None:
            website.is_active = update_data.is_active

        website.updated_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(website)

        return website

    def delete_website(self, website_id: UUID, user_id: UUID) -> None:
        """
        Soft delete a website.

        Args:
            website_id: ID of the website
            user_id: ID of the user (for authorization)

        Raises:
            HTTPException: If website not found or not owned by user
        """
        website = self.get_website(website_id, user_id)
        website.soft_delete()
        self.db.commit()

    # ================================================================
    # Helper Methods
    # ================================================================

    def _validate_url(self, url: str) -> None:
        """
        Validate URL format.

        Args:
            url: URL to validate

        Raises:
            HTTPException: If URL is invalid
        """
        if not url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL is required"
            )

        # Basic URL validation
        url_pattern = re.compile(
            r'^(https?://)?'  # Optional protocol
            r'([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)'  # Domain
            r'(:\d+)?'  # Optional port
            r'(/.*)?$'  # Optional path
        )

        if not url_pattern.match(url):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid URL format"
            )

    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL (add https:// if missing).

        Args:
            url: URL to normalize

        Returns:
            str: Normalized URL
        """
        if not url.startswith(('http://', 'https://')):
            return f"https://{url}"
        return url

    def get_user_websites_count(self, user_id: UUID) -> int:
        """
        Get total count of websites for a user.

        Args:
            user_id: ID of the user

        Returns:
            int: Total count of websites
        """
        return self.db.query(Website).filter(
            Website.user_id == user_id,
            Website.deleted_at == None
        ).count()