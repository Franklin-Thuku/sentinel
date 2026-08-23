"""
User service for Sentinel.

Handles business logic for user management including registration,
authentication, profile management, and password operations.
"""

from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.db.models.user import User
from app.db.models.organization import Organization
from app.db.models.audit_log import AuditLog
from app.core.security import (
    get_password_hash,
    verify_password,
    create_tokens,
    decode_token,
    verify_token_type,
    create_access_token,
    get_token_expires_in,
)
from app.schemas.user import UserRegister, UserUpdate, PasswordChange


class UserService:
    """
    Service for user-related business logic.
    """

    def __init__(self, db: Session):
        """
        Initialize the user service with a database session.

        Args:
            db: SQLAlchemy database session
        """
        self.db = db

    # ================================================================
    # User Registration
    # ================================================================

    def register_user(self, user_data: UserRegister) -> User:
        """
        Register a new user.

        Args:
            user_data: User registration data (email, password, full_name)

        Returns:
            User: The created user

        Raises:
            HTTPException: If email already exists
        """
        # Check if user already exists
        existing_user = self.db.query(User).filter(
            User.email == user_data.email
        ).first()

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        # Hash the password
        hashed_password = get_password_hash(user_data.password)

        # Create new user
        new_user = User(
            email=user_data.email,
            password_hash=hashed_password,
            full_name=user_data.full_name,
            role="user",
            is_active=True,
            is_email_verified=False,
        )

        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)

        # Create default organization for the user
        self._create_default_organization(new_user)

        # Log the registration
        self._log_audit_event(
            user_id=new_user.id,
            action="user_register",
            resource_type="user",
            resource_id=str(new_user.id),
            details={"email": new_user.email},
        )

        return new_user

    def _create_default_organization(self, user: User) -> Organization:
        """
        Create a default organization for a user.

        Args:
            user: The user

        Returns:
            Organization: The created organization
        """
        import secrets

        slug = f"org-{secrets.token_urlsafe(8)}".lower()

        organization = Organization(
            name=f"{user.full_name}'s Organization",
            slug=slug,
            is_active=True,
            settings={"default": True},
        )

        self.db.add(organization)
        self.db.commit()
        self.db.refresh(organization)

        # Add user to organization
        organization.users.append(user)
        self.db.commit()

        return organization

    # ================================================================
    # User Authentication
    # ================================================================

    def authenticate_user(self, email: str, password: str) -> User:
        """
        Authenticate a user by email and password.

        Args:
            email: User's email address
            password: User's password

        Returns:
            User: The authenticated user

        Raises:
            HTTPException: If credentials are invalid
        """
        # Find user by email
        user = self.db.query(User).filter(
            User.email == email
        ).first()

        # Check if user exists and is active
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is deactivated",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify password
        if not verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Update last login timestamp
        user.record_login()
        self.db.commit()

        # Log the login
        self._log_audit_event(
            user_id=user.id,
            action="user_login",
            resource_type="user",
            resource_id=str(user.id),
            details={"email": user.email},
        )

        return user

    # ================================================================
    # Token Management
    # ================================================================

    def create_user_tokens(self, user: User) -> dict:
        """
        Create access and refresh tokens for a user.

        Args:
            user: The authenticated user

        Returns:
            dict: Token response with access_token, refresh_token, etc.
        """
        tokens = create_tokens(str(user.id), user.email)
        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": tokens["token_type"],
            "expires_in": tokens["expires_in"],
            "user": user,
        }

    def refresh_access_token(self, refresh_token: str) -> dict:
        """
        Refresh an access token using a refresh token.

        Args:
            refresh_token: The refresh token

        Returns:
            dict: New access token

        Raises:
            HTTPException: If refresh token is invalid
        """
        # Decode and verify the refresh token
        payload = decode_token(refresh_token)

        # Verify it's a refresh token
        if not verify_token_type(payload, "refresh"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user from token
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Find user
        user = self.get_user_by_id(UUID(user_id))
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Create new access token
        token_data = {"sub": str(user.id), "email": user.email}
        new_access_token = create_access_token(token_data)

        # Log the token refresh
        self._log_audit_event(
            user_id=user.id,
            action="token_refresh",
            resource_type="user",
            resource_id=str(user.id),
            details={"token_type": "access"},
        )

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": get_token_expires_in(),
        }

    # ================================================================
    # User Retrieval
    # ================================================================

    def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """
        Get a user by ID.

        Args:
            user_id: The user's UUID

        Returns:
            Optional[User]: The user if found, None otherwise
        """
        return self.db.query(User).filter(
            User.id == user_id,
            User.deleted_at.is_(None)
        ).first()

    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get a user by email.

        Args:
            email: The user's email address

        Returns:
            Optional[User]: The user if found, None otherwise
        """
        return self.db.query(User).filter(
            User.email == email,
            User.deleted_at.is_(None)
        ).first()

    def get_user_with_organizations(self, user_id: UUID) -> Optional[User]:
        """
        Get a user with their organizations loaded.

        Args:
            user_id: The user's UUID

        Returns:
            Optional[User]: The user with organizations loaded
        """
        return self.db.query(User).filter(
            User.id == user_id,
            User.deleted_at.is_(None)
        ).first()

    # ================================================================
    # User Management
    # ================================================================

    def update_user_profile(self, user_id: UUID, update_data: UserUpdate) -> User:
        """
        Update a user's profile.

        Args:
            user_id: The user's UUID
            update_data: The data to update

        Returns:
            User: The updated user

        Raises:
            HTTPException: If user not found or email already taken
        """
        user = self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Update fields
        if update_data.full_name is not None:
            user.full_name = update_data.full_name

        if update_data.email is not None and update_data.email != user.email:
            # Check if email is already taken
            existing = self.get_user_by_email(update_data.email)
            if existing and existing.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )
            user.email = update_data.email
            user.is_email_verified = False  # Require re-verification

        self.db.commit()
        self.db.refresh(user)

        # Log the update
        self._log_audit_event(
            user_id=user.id,
            action="user_update",
            resource_type="user",
            resource_id=str(user.id),
            details={"updated_fields": update_data.dict(exclude_unset=True)},
        )

        return user

    def change_password(self, user_id: UUID, password_data: PasswordChange) -> User:
        """
        Change a user's password.

        Args:
            user_id: The user's UUID
            password_data: Current and new password

        Returns:
            User: The updated user

        Raises:
            HTTPException: If user not found or current password is incorrect
        """
        user = self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Verify current password
        if not verify_password(password_data.current_password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect"
            )

        # Hash and set new password
        user.password_hash = get_password_hash(password_data.new_password)

        self.db.commit()
        self.db.refresh(user)

        # Log the password change
        self._log_audit_event(
            user_id=user.id,
            action="password_change",
            resource_type="user",
            resource_id=str(user.id),
            details={"password_changed": True},
        )

        return user

    def soft_delete_user(self, user_id: UUID) -> None:
        """
        Soft delete a user account.

        Args:
            user_id: The user's UUID

        Raises:
            HTTPException: If user not found
        """
        user = self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Don't allow deletion of the last admin
        admin_count = self.db.query(User).filter(
            User.role.in_(["admin", "super_admin"]),
            User.deleted_at.is_(None)
        ).count()

        if user.role in ["admin", "super_admin"] and admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the last admin user"
            )

        user.soft_delete()
        self.db.commit()

        # Log the deletion
        self._log_audit_event(
            user_id=user.id,
            action="user_delete",
            resource_type="user",
            resource_id=str(user.id),
            details={"soft_delete": True},
        )

    def reactivate_user(self, user_id: UUID) -> User:
        """
        Reactivate a soft-deleted user account.

        Args:
            user_id: The user's UUID

        Returns:
            User: The reactivated user

        Raises:
            HTTPException: If user not found
        """
        # Find user including soft-deleted
        user = self.db.query(User).filter(
            User.id == user_id
        ).first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        user.restore()
        self.db.commit()
        self.db.refresh(user)

        # Log the reactivation
        self._log_audit_event(
            user_id=user.id,
            action="user_reactivate",
            resource_type="user",
            resource_id=str(user.id),
            details={"reactivated": True},
        )

        return user

    def verify_email(self, user_id: UUID) -> User:
        """
        Mark user's email as verified.

        Args:
            user_id: The user's UUID

        Returns:
            User: The updated user

        Raises:
            HTTPException: If user not found
        """
        user = self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        user.mark_email_verified()
        self.db.commit()
        self.db.refresh(user)

        # Log the verification
        self._log_audit_event(
            user_id=user.id,
            action="email_verify",
            resource_type="user",
            resource_id=str(user.id),
            details={"email_verified": True},
        )

        return user

    # ================================================================
    # User Statistics
    # ================================================================

    def get_user_stats(self, user_id: UUID) -> dict:
        """
        Get user statistics.

        Args:
            user_id: ID of the user

        Returns:
            dict: User statistics
        """
        from app.db.models.website import Website
        from app.db.models.scan import Scan
        from app.db.models.alert import Alert

        # Count websites
        websites_count = self.db.query(Website).filter(
            Website.user_id == user_id,
            Website.deleted_at.is_(None)
        ).count()

        # Count scans
        scans_count = self.db.query(Scan).filter(
            Scan.user_id == user_id
        ).count()

        # Count active alerts
        alerts_count = self.db.query(Alert).filter(
            Alert.user_id == user_id,
            Alert.is_read == False,
            Alert.is_dismissed == False
        ).count()

        return {
            "websites_count": websites_count,
            "scans_count": scans_count,
            "alerts_count": alerts_count,
        }

    # ================================================================
    # Organization Management
    # ================================================================

    def get_user_organizations(self, user_id: UUID) -> list:
        """
        Get all organizations a user belongs to.

        Args:
            user_id: ID of the user

        Returns:
            list: List of organizations
        """
        user = self.get_user_by_id(user_id)
        if not user:
            return []
        return user.organizations

    def get_organization_users(self, organization_id: UUID) -> list:
        """
        Get all users in an organization.

        Args:
            organization_id: ID of the organization

        Returns:
            list: List of users in the organization
        """
        organization = self.db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not organization:
            return []

        return organization.users

    def add_user_to_organization(self, user_id: UUID, organization_id: UUID) -> None:
        """
        Add a user to an organization.

        Args:
            user_id: ID of the user
            organization_id: ID of the organization

        Raises:
            HTTPException: If user or organization not found
        """
        user = self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        organization = self.db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        if user not in organization.users:
            organization.users.append(user)
            self.db.commit()

            # Log the addition
            self._log_audit_event(
                user_id=user.id,
                action="organization_user_add",
                resource_type="organization",
                resource_id=str(organization_id),
                details={"added_user_id": str(user_id)},
            )

    def remove_user_from_organization(self, user_id: UUID, organization_id: UUID) -> None:
        """
        Remove a user from an organization.

        Args:
            user_id: ID of the user
            organization_id: ID of the organization

        Raises:
            HTTPException: If user or organization not found
        """
        user = self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        organization = self.db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        if user in organization.users:
            organization.users.remove(user)
            self.db.commit()

            # Log the removal
            self._log_audit_event(
                user_id=user.id,
                action="organization_user_remove",
                resource_type="organization",
                resource_id=str(organization_id),
                details={"removed_user_id": str(user_id)},
            )

    # ================================================================
    # Audit Logging
    # ================================================================

    def _log_audit_event(
        self,
        user_id: UUID,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """
        Log an audit event.

        Args:
            user_id: ID of the user
            action: Action performed
            resource_type: Type of resource
            resource_id: ID of the resource
            details: Additional details
            ip_address: IP address of the request
            user_agent: User agent of the request
        """
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            severity="info",
            status="success",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self.db.add(audit_log)
        self.db.commit()