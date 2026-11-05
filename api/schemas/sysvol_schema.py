"""
ZclockID Enterprise Management Appliance - Sysvol Replication Schemas
Pydantic input and output validation models for multi-master Sysvol synchronization and partner topology.
"""

from pydantic import BaseModel, Field
from typing import Optional

class SysvolPartnerRequest(BaseModel):
    name: str = Field(..., example="DC2-Secondary")
    ip_address: str = Field(..., example="192.168.1.42")
    shared_secret: str = Field(..., example="PartnerSyncSecret2026!")

class SysvolFileUploadRequest(BaseModel):
    rel_path: str = Field(..., example="inet.net/Policies/{GUID}/GPT.INI")
    content_base64: str
    mtime: Optional[float] = None
