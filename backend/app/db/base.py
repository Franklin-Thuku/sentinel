"""
Database base configuration for Sentinel.

This module sets up the SQLAlchemy foundation for the entire application.
It provides:
- The declarative base class that all models inherit from
- The database engine (connection pool, configuration)
- The session factory for database operations

All database models in `app.db.models` inherit from `Base`.
All database operations use `SessionLocal` to create sessions.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

from app.config import settings


# ================================================================
# Database Engine
# ================================================================

engine = create_engine(
    settings.DATABASE_URL,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    echo=settings.DB_ECHO,
    # PostgreSQL-specific optimizations
    pool_pre_ping=True,  # Verify connections before using them
    pool_recycle=3600,   # Recycle connections after 1 hour
)


# ================================================================
# Declarative Base
# ================================================================

Base = declarative_base()


# ================================================================
# Session Factory
# ================================================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# ================================================================
# Database Session Dependency
# ================================================================

def get_db() -> Generator[Session, None, None]:
    """
    Dependency for FastAPI endpoints that need database access.

    Creates a new database session for each request and ensures it's
    properly closed after the request completes.

    Usage:
        @app.get("/users")
        async def get_users(db: Session = Depends(get_db)):
            return db.query(User).all()

    Yields:
        Session: A SQLAlchemy session for database operations.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ================================================================
# Database Initialization
# ================================================================

def init_db() -> None:
    """
    Initialize the database by creating all tables.

    This should only be used in development or testing environments.
    In production, use Alembic migrations instead.

    Warning:
        This will drop existing tables if they exist!
        Only use this in development or testing.
    """
    Base.metadata.create_all(bind=engine)


def drop_db() -> None:
    """
    Drop all tables from the database.

    Warning:
        This will DELETE ALL DATA!
        Only use this in development or testing.
    """
    Base.metadata.drop_all(bind=engine)


# ================================================================
# Helper Functions
# ================================================================

def get_engine_url() -> str:
    """
    Get the database URL (with password masked for logging).

    Returns:
        str: The database URL with password masked.
    """
    url = settings.DATABASE_URL
    # Mask password for logging
    if "@" in url:
        # postgresql://user:password@host/db
        # postgresql://user:****@host/db
        parts = url.split("@")
        if ":" in parts[0]:
            # postgresql://user:password
            # postgresql://user:****
            prefix = parts[0]
            if ":" in prefix:
                scheme_user, password = prefix.rsplit(":", 1)
                return f"{scheme_user}:****@{parts[1]}"
    return url


def get_db_status() -> dict:
    """
    Get database connection status.

    Returns:
        dict: Status information about the database connection.
    """
    try:
        # Try to connect and execute a simple query
        with engine.connect() as conn:
            result = conn.execute("SELECT 1")
            return {
                "status": "healthy",
                "url": get_engine_url(),
                "pool_size": engine.pool.size(),
                "checked_in": engine.pool.checkedin(),
                "overflow": engine.pool.overflow(),
                "total": engine.pool.total(),
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "url": get_engine_url(),
            "error": str(e),
        }