"""
ZclockID Authentication and Setup Schemas
"""

from typing import Optional
from pydantic import BaseModel, Field

class SetupProvisionRequest(BaseModel):
    admin_username: str = Field("admin", example="admin")
    admin_password: str = Field(..., min_length=8, example="AdminP@ssw0rd2026!")
    admin_email: Optional[str] = Field("admin@corp.example.com", example="admin@corp.example.com")
    mode: str = Field("new_domain", pattern="^(new_domain|join_domain)$")
    realm: str = Field(..., example="CORP.EXAMPLE.COM")
    domain_netbios: str = Field(..., example="CORP")
    ad_admin_password: str = Field(..., min_length=8, example="DomainP@ssw0rd2026!")
    dns_forwarder: Optional[str] = Field("1.1.1.1 8.8.8.8", example="1.1.1.1 8.8.8.8")
    partner_dc_ip: Optional[str] = Field(None, example="192.168.1.23")
    ad_admin_user: Optional[str] = Field("Administrator", example="Administrator")

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, description="Minimum 8 characters")

class BreakGlassUpdateRequest(BaseModel):
    new_password: Optional[str] = Field(None, min_length=8)
    email: Optional[str] = Field(None)

