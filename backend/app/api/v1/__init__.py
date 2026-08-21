"""
API v1 - Main Router

This module aggregates all v1 API endpoints.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import health

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(health.router, prefix="/health", tags=["Health"])