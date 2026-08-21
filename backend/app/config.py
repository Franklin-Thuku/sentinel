"""
Configuration management for Sentinel backend.

Loads environment variables, validates them, and provides a
typed configuration object for the entire application.
"""

from typing import Optional, Literal, List
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings
import os


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.

    All sensitive values (secrets, API keys) are stored as SecretStr
    to prevent accidental exposure in logs or error messages.
    """

    # ================================================================
    # Application
    # ================================================================
    APP_NAME: str = "Sentinel"
    APP_VERSION: str = "1.0.0"
    APP_ENV: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # ================================================================
    # Security
    # ================================================================
    SECRET_KEY: SecretStr = Field(..., description="Must be 32+ characters")
    JWT_SECRET: SecretStr = Field(..., description="Must be 32+ characters")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PASSWORD_HASHING_ALGORITHM: Literal["bcrypt", "argon2id"] = "argon2id"
    BCRYPT_ROUNDS: int = 12
    ARGON2_TIME_COST: int = 2
    ARGON2_MEMORY_COST: int = 65536
    ARGON2_PARALLELISM: int = 1
    ARGON2_HASH_LEN: int = 32

    # ================================================================
    # Database
    # ================================================================
    DATABASE_URL: str = Field(..., description="PostgreSQL connection string")
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_ECHO: bool = False

    # ================================================================
    # Redis
    # ================================================================
    REDIS_URL: str = Field(..., description="Redis connection string")
    REDIS_MAX_CONNECTIONS: int = 10

    # ================================================================
    # CORS
    # ================================================================
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3000",
    ]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]

    # ================================================================
    # Rate Limiting
    # ================================================================
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/hour"
    RATE_LIMIT_AUTH: str = "20/minute"
    RATE_LIMIT_SCAN: str = "10/hour"
    RATE_LIMIT_API: str = "1000/minute"

    # ================================================================
    # Scanning
    # ================================================================
    SCAN_MAX_URLS: int = 100
    SCAN_MAX_RESPONSE_SIZE: int = 10 * 1024 * 1024  # 10MB
    SCAN_REQUEST_TIMEOUT: int = 30  # seconds
    SCAN_TOTAL_TIMEOUT: int = 600  # 10 minutes
    SCAN_MAX_REDIRECTS: int = 10
    SCAN_MAX_CONCURRENT_REQUESTS: int = 10
    SCAN_RATE_LIMIT_REQUESTS: int = 50
    SCAN_RATE_LIMIT_PERIOD: int = 60  # seconds
    SCAN_USER_AGENT: str = (
        "Sentinel-Security-Scanner/1.0 "
        "(https://sentinel.example.com; security@sentinel.example.com)"
    )
    SCAN_ALLOWED_PORTS: List[int] = [80, 443, 8080, 8443]
    SCAN_MAX_DEPTH: int = 3
    SCAN_DISCOVERY_LIMIT: int = 50

    # ================================================================
    # SSRF Protection
    # ================================================================
    SSRF_BLOCK_PRIVATE_IPS: bool = True
    SSRF_BLOCK_LOOPBACK: bool = True
    SSRF_BLOCK_LINK_LOCAL: bool = True
    SSRF_BLOCK_METADATA_IPS: bool = True
    SSRF_ALLOWED_SCHEMES: List[str] = ["http", "https"]
    SSRF_DNS_CACHE_TTL: int = 300  # seconds
    SSRF_MAX_IP_LOOKUPS: int = 5

    # ================================================================
    # AI
    # ================================================================
    AI_PROVIDER: Optional[Literal["openai", "anthropic", "google", "mock"]] = None
    AI_API_KEY: Optional[SecretStr] = None
    AI_MODEL: Optional[str] = None
    AI_MAX_TOKENS: int = 4096
    AI_TEMPERATURE: float = 0.3
    AI_TIMEOUT: int = 60  # seconds
    AI_RETRY_ATTEMPTS: int = 3
    AI_RETRY_DELAY: int = 2  # seconds

    # ================================================================
    # Email
    # ================================================================
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: Optional[int] = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[SecretStr] = None
    SMTP_FROM_EMAIL: Optional[str] = None
    SMTP_FROM_NAME: str = "Sentinel Security"
    SMTP_USE_TLS: bool = True
    SMTP_TIMEOUT: int = 30

    # ================================================================
    # Frontend
    # ================================================================
    FRONTEND_URL: str = "http://localhost:3000"
    FRONTEND_VERIFICATION_PATH: str = "/verify"

    # ================================================================
    # Admin
    # ================================================================
    ADMIN_EMAILS: List[str] = ["admin@sentinel.example.com"]

    # ================================================================
    # Celery
    # ================================================================
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None
    CELERY_TASK_ALWAYS_EAGER: bool = False
    CELERY_TASK_TRACK_STARTED: bool = True
    CELERY_TASK_TIME_LIMIT: int = 600  # seconds
    CELERY_TASK_SOFT_TIME_LIMIT: int = 540  # seconds

    # ================================================================
    # Monitoring
    # ================================================================
    MONITORING_CHECK_INTERVAL_MINUTES: int = 60
    MONITORING_ALERT_COOLDOWN_HOURS: int = 24
    MONITORING_MAX_RETRIES: int = 3

    # ================================================================
    # Subscription
    # ================================================================
    SUBSCRIPTION_ENABLED: bool = False
    STRIPE_API_KEY: Optional[SecretStr] = None
    STRIPE_WEBHOOK_SECRET: Optional[SecretStr] = None
    STRIPE_PRICE_FREE: Optional[str] = None
    STRIPE_PRICE_PRO: Optional[str] = None
    STRIPE_PRICE_AGENCY: Optional[str] = None

    # ================================================================
    # Usage Limits
    # ================================================================
    FREE_WEBSITE_LIMIT: int = 1
    FREE_SCAN_LIMIT_PER_MONTH: int = 5
    FREE_AI_ANALYSIS_LIMIT: int = 5
    PRO_WEBSITE_LIMIT: int = 25
    PRO_SCAN_LIMIT_PER_MONTH: int = 100
    PRO_AI_ANALYSIS_LIMIT: int = 100
    AGENCY_WEBSITE_LIMIT: int = 500
    AGENCY_SCAN_LIMIT_PER_MONTH: int = 1000
    AGENCY_AI_ANALYSIS_LIMIT: int = 1000

    # ================================================================
    # Logging
    # ================================================================
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    LOG_JSON_FORMAT: bool = False
    LOG_INCLUDE_TIMESTAMP: bool = True
    LOG_INCLUDE_LEVEL: bool = True
    LOG_INCLUDE_LOGGER: bool = True

    # ================================================================
    # Security Headers (for Sentinel's own responses)
    # ================================================================
    SECURE_HSTS_MAX_AGE: int = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS: bool = True
    SECURE_HSTS_PRELOAD: bool = True
    SECURE_CSP_DIRECTIVES: str = "default-src 'self'; frame-ancestors 'none'"

    # ================================================================
    # Session
    # ================================================================
    SESSION_COOKIE_NAME: str = "sentinel_session"
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    SESSION_COOKIE_MAX_AGE: int = 3600  # 1 hour

    # ================================================================
    # Validation Methods
    # ================================================================

    @field_validator("SECRET_KEY", "JWT_SECRET")
    @classmethod
    def validate_secret_keys(cls, v: SecretStr) -> SecretStr:
        """Ensure secret keys are at least 32 characters."""
        if len(v.get_secret_value()) < 32:
            raise ValueError("Secret must be at least 32 characters long")
        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """Ensure database URL uses the correct scheme."""
        if not v.startswith(("postgresql://", "postgresql+asyncpg://")):
            if v.startswith("postgres://"):
                v = v.replace("postgres://", "postgresql://", 1)
            else:
                raise ValueError(
                    "DATABASE_URL must start with postgresql:// or postgresql+asyncpg://"
                )
        return v

    @field_validator("REDIS_URL")
    @classmethod
    def validate_redis_url(cls, v: str) -> str:
        """Ensure Redis URL is valid."""
        if not v.startswith(("redis://", "rediss://")):
            raise ValueError("REDIS_URL must start with redis:// or rediss://")
        return v

    @field_validator("AI_PROVIDER")
    @ classmethod
    def validate_ai_provider(cls, v: Optional[str]) -> Optional[str]:
        """Validate AI provider configuration."""
        if v and v not in ["openai", "anthropic", "google", "mock"]:
            raise ValueError(f"Invalid AI_PROVIDER: {v}")
        return v

    @field_validator("SCAN_ALLOWED_PORTS")
    @classmethod
    def validate_ports(cls, v: List[int]) -> List[int]:
        """Ensure ports are in valid range."""
        for port in v:
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}. Must be between 1 and 65535")
        return v

    @field_validator("CORS_ORIGINS")
    @classmethod
    def validate_cors_origins(cls, v: List[str]) -> List[str]:
        """Ensure CORS origins are valid URLs."""
        for origin in v:
            if not origin.startswith(("http://", "https://")):
                raise ValueError(f"Invalid CORS origin: {origin}. Must start with http:// or https://")
        return v

    @field_validator("SCAN_USER_AGENT")
    @classmethod
    def validate_user_agent(cls, v: str) -> str:
        """Ensure user agent is not empty and has contact info."""
        if not v.strip():
            raise ValueError("SCAN_USER_AGENT cannot be empty")
        if "security@" not in v and "contact" not in v:
            # Warning only, not an error
            pass
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"


# ================================================================
# Singleton Instance
# ================================================================

settings = Settings()


def get_settings() -> Settings:
    """
    Dependency injection for settings.

    Usage:
        from app.config import get_settings

        @app.get("/health")
        async def health(settings: Settings = Depends(get_settings)):
            return {"status": "ok", "env": settings.APP_ENV}
    """
    return settings


# ================================================================
# Helper Functions
# ================================================================

def is_development() -> bool:
    """Check if running in development environment."""
    return settings.APP_ENV == "development"


def is_staging() -> bool:
    """Check if running in staging environment."""
    return settings.APP_ENV == "staging"


def is_production() -> bool:
    """Check if running in production environment."""
    return settings.APP_ENV == "production"


def is_testing() -> bool:
    """Check if running in testing environment."""
    return settings.APP_ENV == "testing" or "pytest" in sys.modules


import sys