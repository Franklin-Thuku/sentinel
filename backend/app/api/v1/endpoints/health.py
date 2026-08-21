"""
Health Check Endpoints

Provides health and readiness checks for the API.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import get_db

router = APIRouter()


@router.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": "sentinel-api",
    }


@router.get("/health/db")
async def db_health_check(db: Session = Depends(get_db)):
    """Database health check endpoint."""
    try:
        # Test the database connection
        db.execute(text("SELECT 1"))
        return {
            "status": "healthy",
            "database": "connected",
            "message": "Database is operational",
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
        }