"""
ZclockID Appliance System Security & Network Baseline Schemas
"""

from typing import Optional, List
from pydantic import BaseModel, Field

class SecuritySettingsUpdateRequest(BaseModel):
    session_idle_timeout_min: int = Field(15, ge=0, le=1440, description="Idle timeout in minutes before auto-logout (0 to disable)")
    session_max_lifetime_hours: int = Field(8, ge=1, le=168, description="Maximum absolute session duration in hours")
    allowed_subnets_gui: str = Field("0.0.0.0/0, ::/0", description="Comma-separated CIDRs allowed to access Web GUI and API")
    allowed_subnets_ssh: str = Field("0.0.0.0/0, ::/0", description="Comma-separated CIDRs allowed for SSH port 22")
    allowed_subnets_snmp: str = Field("192.168.1.0/24, 10.10.0.0/24, 127.0.0.1/32", description="Comma-separated CIDRs allowed for SNMP port 161")
    snmp_community: str = Field("zclock_public", min_length=1, max_length=64, description="SNMP read-only community string")
    max_failed_logins: int = Field(5, ge=1, le=50, description="Max failed login attempts before lockout")
    lockout_duration_min: int = Field(15, ge=1, le=1440, description="Lockout duration in minutes")
    ssh_permit_root: int = Field(0, ge=0, le=1, description="Allow SSH root login (0=No, 1=Yes)")
    ssh_password_auth: int = Field(1, ge=0, le=1, description="Allow SSH password authentication (0=Key Only, 1=Password Allowed)")

class SecuritySettingsResponse(BaseModel):
    session_idle_timeout_min: int
    session_max_lifetime_hours: int
    allowed_subnets_gui: str
    allowed_subnets_ssh: str
    allowed_subnets_snmp: str
    snmp_community: str
    max_failed_logins: int
    lockout_duration_min: int
    ssh_permit_root: int
    ssh_password_auth: int
    updated_at: float
    current_client_ip: str
    ssh_service_active: bool = True
    snmp_service_active: bool = True

class ActiveSessionItem(BaseModel):
    token_prefix: str
    username: str
    role: str
    ip_address: str
    user_agent: str
    created_at: float
    last_active: float
    is_current: bool = False
