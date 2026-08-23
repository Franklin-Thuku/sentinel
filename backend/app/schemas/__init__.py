"""
Schemas module for Sentinel.

Defines Pydantic models for request/response validation.
"""

from app.schemas.user import (
    UserCreate,
    UserRegister,
    UserUpdate,
    UserResponse,
    UserListResponse,
    UserLogin,
    TokenResponse,
    PasswordChange,
    PasswordResetRequest,
    PasswordResetConfirm,
)
from app.schemas.security import (
    RefreshTokenRequest,
    ChangePasswordRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
)
from app.schemas.website import (
    WebsiteCreate,
    WebsiteUpdate,
    WebsiteResponse,
    WebsiteListResponse,
    WebsiteVerifyRequest,
    WebsiteVerifyResponse,
)
from app.schemas.scan import (
    ScanCreate,
    ScanUpdate,
    ScanResponse,
    ScanListResponse,
    ScanStatusResponse,
)
from app.schemas.finding import (
    FindingResponse,
    FindingUpdate,
    FindingListResponse,
)
from app.schemas.report import (
    ReportResponse,
    ReportListResponse,
    ReportGenerateRequest,
)
from app.schemas.alert import (
    AlertResponse,
    AlertListResponse,
    AlertUpdate,
)
from app.schemas.monitoring import (
    MonitoringConfigCreate,
    MonitoringConfigUpdate,
    MonitoringConfigResponse,
    MonitoringConfigListResponse,
)

__all__ = [
    # User
    "UserCreate",
    "UserRegister",
    "UserUpdate",
    "UserResponse",
    "UserListResponse",
    "UserLogin",
    "TokenResponse",
    "PasswordChange",
    "PasswordResetRequest",
    "PasswordResetConfirm",
    # Security
    "RefreshTokenRequest",
    "ChangePasswordRequest",
    # Website
    "WebsiteCreate",
    "WebsiteUpdate",
    "WebsiteResponse",
    "WebsiteListResponse",
    "WebsiteVerifyRequest",
    "WebsiteVerifyResponse",
    # Scan
    "ScanCreate",
    "ScanUpdate",
    "ScanResponse",
    "ScanListResponse",
    "ScanStatusResponse",
    # Finding
    "FindingResponse",
    "FindingUpdate",
    "FindingListResponse",
    # Report
    "ReportResponse",
    "ReportListResponse",
    "ReportGenerateRequest",
    # Alert
    "AlertResponse",
    "AlertListResponse",
    "AlertUpdate",
    # Monitoring
    "MonitoringConfigCreate",
    "MonitoringConfigUpdate",
    "MonitoringConfigResponse",
    "MonitoringConfigListResponse",
]