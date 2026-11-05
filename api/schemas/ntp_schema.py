"""
ZclockID NTP Management Schemas
"""

from typing import List, Optional
from pydantic import BaseModel, Field

class NtpConfigRequest(BaseModel):
    ntp_server_enabled: bool = True
    allowed_subnets: str = "0.0.0.0/0, ::/0"
    ms_sntp_enabled: bool = True
    upstream_servers: List[str] = Field(default_factory=lambda: ["time.google.com", "pool.ntp.org", "time.windows.com"])
    timezone: Optional[str] = None

