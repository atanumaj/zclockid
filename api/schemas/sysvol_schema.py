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
    cert_fingerprint: Optional[str] = Field(None, example="6D:41:53:BF:D5:51:93:FE:5C:65:23:12:4C:71:35:AF:E4:3A:28:14:B3:77:F9:CE:7B:4B:C2:B7:35:07:F5:E3")

class SysvolFileUploadRequest(BaseModel):
    rel_path: str = Field(..., example="example.com/Policies/{GUID}/GPT.INI")
    content_base64: str
    mtime: Optional[float] = None

