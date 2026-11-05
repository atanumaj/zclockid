"""
ZclockID Remote Syslog & Audit Streaming Schemas
"""

from typing import Optional, List
from pydantic import BaseModel, Field

class SyslogConfigRequest(BaseModel):
    enabled: bool = True
    remote_host: str = Field(..., example="192.168.1.50")
    remote_port: int = Field(514, ge=1, le=65535, example=514)
    protocol: str = Field("UDP", pattern="^(UDP|TCP|TLS)$", example="UDP")
    facility: str = Field("local0", example="local0")
    log_format: str = Field("RFC5424", pattern="^(RFC5424|RFC3164)$", example="RFC5424")
    send_samba_logs: bool = True
    send_radius_logs: bool = True
    send_auth_logs: bool = True
    send_system_logs: bool = True

class SyslogTestEventRequest(BaseModel):
    message: Optional[str] = "ZclockID Syslog Test Probe Event"
