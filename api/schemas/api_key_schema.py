"""
ZclockID API Key Management Schemas
"""

from typing import Optional, List
from pydantic import BaseModel, Field

VALID_SCOPES = [
    "admin:all",
    "users:manage",
    "radius:read",
    "telemetry:read",
    "dns:manage",
    "sysvol:read"
]

class ApiKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=64, example="Prometheus Telemetry Scraper")
    scopes: List[str] = Field(..., example=["telemetry:read"])
    cidr_whitelist: Optional[str] = Field("0.0.0.0/0", example="192.168.1.0/24")
    expires_days: Optional[int] = Field(None, example=90)  # None = Never expires

class ApiKeyCreateResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    full_api_key: str  # Displayed once upon creation
    scopes: List[str]
    cidr_whitelist: str
    expires_at: Optional[float]
    created_at: float

class ApiKeyItemResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    scopes: List[str]
    cidr_whitelist: str
    expires_at: Optional[float]
    last_used_at: Optional[float]
    is_active: bool
    created_at: float
