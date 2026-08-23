"""
Website API endpoints for Sentinel.

Handles website management: create, list, get, update, delete websites.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.db.models.user import User
from app.db.models.website import Website
from app.schemas.website import WebsiteCreate, WebsiteUpdate, WebsiteResponse, WebsiteListResponse
from app.services.website_service import WebsiteService

router = APIRouter()


# ================================================================
# Website Endpoints
# ================================================================

@router.post(
    "/websites",
    response_model=WebsiteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a website",
    description="Add a new website to monitor."
)
async def create_website(
    website_data: WebsiteCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Create a new website for the current user.

    Args:
        website_data: Website creation data
        current_user: The authenticated user
        db: Database session

    Returns:
        WebsiteResponse: The created website
    """
    service = WebsiteService(db)
    website = service.create_website(current_user.id, website_data)
    return website


@router.get(
    "/websites",
    response_model=WebsiteListResponse,
    summary="List websites",
    description="Get all websites for the current user."
)
async def list_websites(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    search: Optional[str] = Query(None, description="Search by URL or name"),
    organization_id: Optional[UUID] = Query(None, description="Filter by organization"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    List all websites for the current user.

    Args:
        skip: Pagination offset
        limit: Pagination limit
        search: Optional search term
        organization_id: Optional organization filter
        current_user: The authenticated user
        db: Database session

    Returns:
        WebsiteListResponse: List of websites with pagination info
    """
    service = WebsiteService(db)
    websites = service.get_websites(
        user_id=current_user.id,
        organization_id=organization_id,
        skip=skip,
        limit=limit,
        search=search,
    )
    total = service.get_user_websites_count(current_user.id)

    return WebsiteListResponse(
        items=websites,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/websites/{website_id}",
    response_model=WebsiteResponse,
    summary="Get website",
    description="Get a specific website by ID."
)
async def get_website(
    website_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get a specific website by ID.

    Args:
        website_id: ID of the website
        current_user: The authenticated user
        db: Database session

    Returns:
        WebsiteResponse: The website details
    """
    service = WebsiteService(db)
    website = service.get_website(website_id, current_user.id)
    return website


@router.put(
    "/websites/{website_id}",
    response_model=WebsiteResponse,
    summary="Update website",
    description="Update a website's details."
)
async def update_website(
    website_id: UUID,
    update_data: WebsiteUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Update a website.

    Args:
        website_id: ID of the website
        update_data: Update data
        current_user: The authenticated user
        db: Database session

    Returns:
        WebsiteResponse: The updated website
    """
    service = WebsiteService(db)
    website = service.update_website(website_id, current_user.id, update_data)
    return website


@router.delete(
    "/websites/{website_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete website",
    description="Delete a website (soft delete)."
)
async def delete_website(
    website_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Delete a website (soft delete).

    Args:
        website_id: ID of the website
        current_user: The authenticated user
        db: Database session
    """
    service = WebsiteService(db)
    service.delete_website(website_id, current_user.id)
    return None


@router.get(
    "/websites/{website_id}/verify",
    response_model=dict,
    summary="Verify website",
    description="Verify ownership of a website."
)
async def verify_website(
    website_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get verification instructions for a website.

    Args:
        website_id: ID of the website
        current_user: The authenticated user
        db: Database session

    Returns:
        dict: Verification instructions
    """
    service = WebsiteService(db)
    website = service.get_website(website_id, current_user.id)

    # Generate verification token
    import secrets
    token = secrets.token_urlsafe(32)

    # Instructions based on verification method
    instructions = {
        "method": "dns_txt",
        "record": f"_sentinel-verification.{website.domain}",
        "value": f"sentinel-verification={token}",
        "instructions": (
            f"Add a TXT record for `_sentinel-verification.{website.domain}` "
            f"with the value `sentinel-verification={token}`"
        ),
        "alternate_method": "http_file",
        "file_path": "/.well-known/sentinel-verification.txt",
        "file_content": token,
    }

    return {
        "website_id": website_id,
        "domain": website.domain,
        "verification": instructions,
        "message": "Add the TXT record to your DNS settings or the HTTP file to your website",
    }


# ================================================================
# Helper Functions
# ================================================================

def get_website_or_404(
    website_id: UUID,
    user_id: UUID,
    db: Session,
) -> Website:
    """
    Get a website by ID or raise 404.

    Args:
        website_id: ID of the website
        user_id: ID of the user (for authorization)
        db: Database session

    Returns:
        Website: The website

    Raises:
        HTTPException: If website not found
    """
    service = WebsiteService(db)
    website = service.get_website(website_id, user_id)
    if not website:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Website not found"
        )
    return website