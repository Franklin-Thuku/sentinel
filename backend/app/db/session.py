"""
Database session management for Sentinel.

Provides session handling utilities including:
- SessionLocal: Session factory
- get_db(): FastAPI dependency
- Session context manager for manual session management
- Session lifecycle helpers
"""

from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy.orm import Session

from app.db.base import SessionLocal, get_db
from app.db.base import engine


__all__ = [
    "SessionLocal",
    "get_db",
    "get_session",
    "get_db_session",
    "session_scope",
]


def get_session() -> Session:
    """
    Get a new database session.

    Returns:
        Session: A new SQLAlchemy session.
    """
    return SessionLocal()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """
    Provide a transactional scope around a series of operations.

    Usage:
        with session_scope() as session:
            user = session.query(User).first()
            user.email = "new@email.com"
            # Automatically commits on success, rolls back on error

    Yields:
        Session: A SQLAlchemy session with transaction management.
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db_session() -> Generator[Session, None, None]:
    """
    Alias for get_db() - FastAPI dependency for database access.

    Usage:
        @app.get("/users")
        async def get_users(db: Session = Depends(get_db_session)):
            return db.query(User).all()

    Yields:
        Session: A SQLAlchemy session for database operations.
    """
    return get_db()


def get_session_status() -> dict:
    """
    Get current session pool status.

    Returns:
        dict: Session pool status information.
    """
    return {
        "pool_size": engine.pool.size(),
        "checked_in": engine.pool.checkedin(),
        "overflow": engine.pool.overflow(),
        "total": engine.pool.total(),
    }