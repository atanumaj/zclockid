"""
ZclockID Role-Based Access Control (RBAC) Schemas
"""

from typing import Optional, List
from pydantic import BaseModel, Field

VALID_ROLES = ["fulladmin", "operator", "report", "readonly"]
VALID_PRINCIPAL_TYPES = ["group", "user"]

class RbacMappingCreateRequest(BaseModel):
    principal_type: str = Field(..., pattern="^(group|user)$", example="group")
    principal_name: str = Field(..., min_length=1, example="Domain Admins")
    role: str = Field(..., pattern="^(fulladmin|operator|report|readonly)$", example="fulladmin")
    description: Optional[str] = Field(None, example="Active Directory Domain Admins mapped to full admin")

class RbacMappingUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(fulladmin|operator|report|readonly)$", example="operator")
    description: Optional[str] = None

class RbacMappingResponse(BaseModel):
    id: int
    principal_type: str
    principal_name: str
    role: str
    description: Optional[str] = None
    created_at: float
    updated_at: float

class UserPermissionsResponse(BaseModel):
    username: str
    role: str
    is_ad_user: bool
    permissions: List[str]
    groups: List[str] = []
