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
    confirm: Optional[bool] = Field(False, description="Explicit confirmation of probed TLS fingerprint")

class SysvolRepinRequest(BaseModel):
    confirm: Optional[bool] = Field(False, description="Confirm re-pinning of newly probed peer certificate")

class SysvolMassDeleteConfirmRequest(BaseModel):
    detected_at: float = Field(..., description="The detected_at timestamp of the pending mass delete being confirmed")

class SysvolFileUploadRequest(BaseModel):
    rel_path: str = Field(..., example="example.com/Policies/{GUID}/GPT.INI")
    content_base64: str
    sha256: str = Field(..., example="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    mtime: Optional[float] = None
    restore: Optional[bool] = Field(False, description="Whether this file upload is restoring a rejected mass-deleted file")
