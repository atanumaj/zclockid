"""
ZclockID System, Service, Backup, SNMP, and Update Schemas
"""

from typing import Optional, List
from pydantic import BaseModel, Field

class ServiceActionRequest(BaseModel):
    action: str = Field("restart", pattern="^(restart|start|stop|reload|enable|disable)$")

class SystemIdentityUpdateRequest(BaseModel):
    server_description: Optional[str] = None
    hostname: Optional[str] = None
    netbios_name: Optional[str] = None

class BackupCreateRequest(BaseModel):
    backup_type: str = "config_only"  # config_only or full
    description: Optional[str] = "Manual appliance backup"

class BackupRestoreRequest(BaseModel):
    filename: str
    skip_ad_restore: Optional[bool] = False

class BackupInspectRequest(BaseModel):
    filename: str

class SnmpConfigRequest(BaseModel):
    enabled: bool = True
    agent_address: str = "udp:161,udp6:[::1]:161"
    sys_location: str = "Primary Datacenter"
    sys_contact: str = "admin@example.com"
    community_string: str = "zclock_public"
    allowed_subnets: str = "192.168.1.0/24, 127.0.0.1"
    enable_extensions: bool = True
    snmpv3_enabled: bool = False
    snmpv3_user: Optional[str] = "zclock_admin"
    snmpv3_auth_proto: Optional[str] = "SHA"
    snmpv3_priv_proto: Optional[str] = "AES"

class SnmpTestQueryRequest(BaseModel):
    target_host: Optional[str] = "127.0.0.1"
    community_string: Optional[str] = "zclock_public"
    oid: str = ".1.3.6.1.2.1.1.1.0"

class UpdateSettingsModel(BaseModel):
    github_repo: Optional[str] = "atanumaj/zclockid"
    custom_manifest_url: Optional[str] = ""
    auto_check: Optional[bool] = True

class UpdateCheckModel(BaseModel):
    github_repo: Optional[str] = None
    custom_manifest_url: Optional[str] = None

class UpdateInstallModel(BaseModel):
    download_url: Optional[str] = None
    allow_downgrade: Optional[bool] = False

