"""
API v1 Endpoints

This module exports all v1 endpoint routers.
"""

from app.api.v1.endpoints import health
from app.api.v1.endpoints import auth
from app.api.v1.endpoints import websites

__all__ = [
    "health",
    "auth",
    "websites",
]