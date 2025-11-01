"""
Web package exposing the FastAPI application used for the SPA frontend.
"""

from .web import app, create_web_app

__all__ = ["app", "create_web_app"]
