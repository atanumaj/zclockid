"""
ZclockID Enterprise Management Appliance - Domain Schemas
Pydantic input and output validation models for Active Directory Domain Services.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class FunctionalLevelRaiseRequest(BaseModel):
    domain_level: str = Field(..., description="Target Domain Functional Level (e.g. 2016)")
    forest_level: str = Field(..., description="Target Forest Functional Level (e.g. 2016)")

class SystemIdentityUpdateRequest(BaseModel):
    server_description: Optional[str] = Field(None, description="Appliance server description")
    hostname: Optional[str] = Field(None, description="Linux hostname")
    netbios_name: Optional[str] = Field(None, description="Samba NetBIOS computer name")

class UpnSuffixRequest(BaseModel):
    upn_suffix: str = Field(..., description="Alternate domain UPN suffix (e.g. example.com or organization.net)")

class FsmoTransferRequest(BaseModel):
    role: str = Field("all", description="FSMO role name (e.g. all, pdc, naming, schema, rid, infrastructure)")
    force_seize: bool = Field(False, description="Whether to seize the role forcefully if current holder is offline")
    target_server: Optional[str] = Field(None, description="Optional target server IP or hostname (e.g. partner DC for transferring roles)")

