"""
ZclockID Enterprise Management Appliance - Microsoft Entra ID / Azure AD Cloud Sync Schemas
Pydantic input and output validation models for hybrid identity federation.
"""

from pydantic import BaseModel, Field
from typing import Optional

class AzureSyncConfig(BaseModel):
    enabled: bool = False
    tenant_id: str = ""
    client_id: str = ""
    client_secret: Optional[str] = None
    default_domain: Optional[str] = "example.com"
    source_ou: Optional[str] = ""
    sync_interval_seconds: Optional[int] = 900
    exclude_disabled: Optional[bool] = True
    password_hash_sync: Optional[bool] = False
    auto_create_users: Optional[bool] = True

class AzureTestConnectionRequest(BaseModel):
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

