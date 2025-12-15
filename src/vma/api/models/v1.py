from typing import Optional
from pydantic import BaseModel
from datetime import datetime


class Product(BaseModel):
    name: str
    team: str
    description: str | None = None


class Image(BaseModel):
    name: str
    version: str
    product: str
    team: str


class Import(BaseModel):
    scanner: str
    product: str
    image: str
    version: str
    team: str
    data: list


class Team(BaseModel):
    name: str
    description: str | None = None


class User(BaseModel):
    email: str
    password: str
    name: str
    scopes: str
    root: bool


class UserUpdate(BaseModel):
    email: str
    password: str | None = None
    name: str | None = None
    scopes: str | None = None
    root: bool | None = None


class Token(BaseModel):
    access_token: str
    token_type: str


class JwtData(BaseModel):
    username: str
    scope: dict
    root: bool


class CreateTokenRequest(BaseModel):
    """Request model for creating API tokens."""

    username: str
    description: Optional[str] = None
    expires_days: Optional[int] = None  # None = no expiration

    class Config:
        json_schema_extra = {
            "example": {
                "username": "user@vma.com",
                "description": "CI/CD pipeline token",
                "expires_days": 365,
            }
        }


class TokenResponse(BaseModel):
    """Response model for API tokens."""

    id: int
    token: Optional[str] = None  # Only returned once during creation
    prefix: str
    user_email: str
    description: Optional[str]
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    revoked: bool

    class Config:
        json_schema_extra = {
            "example": {
                "id": 123,
                "prefix": "vma_k7j3h2g1",
                "user_email": "user@example.com",
                "description": "CI/CD token",
                "created_at": "2025-12-09T10:00:00Z",
                "last_used_at": "2025-12-09T14:30:00Z",
                "expires_at": "2026-12-09T10:00:00Z",
                "revoked": False,
            }
        }
