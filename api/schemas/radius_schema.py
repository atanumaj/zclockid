"""
ZclockID Enterprise Management Appliance - FreeRADIUS Schemas
Pydantic input and output validation models for NAS Clients, QoS Bandwidth Objects, MAB Devices, and Settings.
"""

from pydantic import BaseModel, Field
from typing import Optional, List

class RadiusClientRequest(BaseModel):
    client_name: str = Field(..., example="floor-1-ap-cluster")
    ip_subnet: str = Field(..., example="192.168.1.0/24")
    shared_secret: str = Field(..., example="RadP@ss2026!")
    shortname: Optional[str] = "ap-cluster"
    nas_type: Optional[str] = "other"

class RadiusBandwidthProfileRequest(BaseModel):
    id: Optional[int] = None
    name: str = Field(..., example="Guest-5M")
    download_mbps: float = Field(..., example=5.0)
    upload_mbps: float = Field(..., example=2.0)
    session_timeout_mins: Optional[int] = 120
    idle_timeout_mins: Optional[int] = 30
    daily_quota_mb: Optional[int] = 0 # 0 for unlimited
    target_type: Optional[str] = "GROUP"
    target_name: Optional[str] = ""
    ad_group: Optional[str] = ""
    is_default: Optional[bool] = False
    description: Optional[str] = ""
    is_active: Optional[bool] = True

class RadiusMabDeviceRequest(BaseModel):
    id: Optional[int] = None
    mac_address: str = Field(..., example="00:11:22:33:44:55")
    device_name: str = Field(..., example="Floor-1-Printer")
    vlan_id: int = Field(..., example=70)
    static_ip: Optional[str] = ""
    description: Optional[str] = ""
    is_active: Optional[bool] = True

class RadiusCustomAttributeRequest(BaseModel):
    id: Optional[int] = None
    target_type: str = Field("GLOBAL", example="GLOBAL")
    target_name: Optional[str] = Field("ALL", example="ALL")
    attribute_name: str = Field(..., example="Session-Timeout")
    operator: Optional[str] = Field("=", example="=")
    attribute_value: str = Field(..., example="28800")
    description: Optional[str] = ""
    is_active: Optional[bool] = True

class RadiusSettingsRequest(BaseModel):
    auth_port: int = 1812
    acct_port: int = 1813
    acct_enabled: bool = True
    interim_interval: int = 300
    listen_ip: Optional[str] = "0.0.0.0"
    log_auth: Optional[bool] = True
    log_badpass: Optional[bool] = True
    log_stripped_names: Optional[bool] = False
    eap_peap_enabled: Optional[bool] = True
    eap_tls_enabled: Optional[bool] = True
    eap_default_type: Optional[str] = "peap"
    max_requests: Optional[int] = 1024
    max_servers: Optional[int] = 32

class DisconnectSessionRequest(BaseModel):
    session_id: str
    username: str
    nas_ip: str
