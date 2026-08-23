"""
Custom exceptions for Sentinel.

Provides domain-specific exception classes for consistent error handling.
"""

from typing import Optional, Any


class SentinelException(Exception):
    """
    Base exception for all Sentinel-specific errors.

    Attributes:
        message: Human-readable error message
        status_code: HTTP status code (if applicable)
        details: Additional error details
    """

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        details: Optional[Any] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(message)


class AuthenticationError(SentinelException):
    """Raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed", details: Optional[Any] = None):
        super().__init__(message, status_code=401, details=details)


class AuthorizationError(SentinelException):
    """Raised when a user lacks permission for an action."""

    def __init__(self, message: str = "Permission denied", details: Optional[Any] = None):
        super().__init__(message, status_code=403, details=details)


class NotFoundError(SentinelException):
    """Raised when a resource is not found."""

    def __init__(self, message: str = "Resource not found", details: Optional[Any] = None):
        super().__init__(message, status_code=404, details=details)


class ValidationError(SentinelException):
    """Raised when input validation fails."""

    def __init__(self, message: str = "Validation failed", details: Optional[Any] = None):
        super().__init__(message, status_code=400, details=details)


class RateLimitError(SentinelException):
    """Raised when a rate limit is exceeded."""

    def __init__(self, message: str = "Rate limit exceeded", details: Optional[Any] = None):
        super().__init__(message, status_code=429, details=details)


class ScanError(SentinelException):
    """Raised when a scan fails."""

    def __init__(self, message: str = "Scan failed", details: Optional[Any] = None):
        super().__init__(message, status_code=500, details=details)


class AIServiceError(SentinelException):
    """Raised when the AI service fails."""

    def __init__(self, message: str = "AI service error", details: Optional[Any] = None):
        super().__init__(message, status_code=503, details=details)


class ReportError(SentinelException):
    """Raised when report generation fails."""

    def __init__(self, message: str = "Report generation failed", details: Optional[Any] = None):
        super().__init__(message, status_code=500, details=details)


class PaymentError(SentinelException):
    """Raised when payment processing fails."""

    def __init__(self, message: str = "Payment processing failed", details: Optional[Any] = None):
        super().__init__(message, status_code=402, details=details)


class UsageLimitError(SentinelException):
    """Raised when usage limits are exceeded."""

    def __init__(self, message: str = "Usage limit exceeded", details: Optional[Any] = None):
        super().__init__(message, status_code=429, details=details)


class VerificationError(SentinelException):
    """Raised when website verification fails."""

    def __init__(self, message: str = "Verification failed", details: Optional[Any] = None):
        super().__init__(message, status_code=400, details=details)