"""
Pydantic Schemas for Appliance Firewall & Port Protection
"""

from typing import Optional, List
from pydantic import BaseModel, Field

class FirewallToggleRequest(BaseModel):
    is_enabled: Optional[bool] = None
    enabled: Optional[bool] = None

    def target_state(self) -> bool:
        if self.is_enabled is not None:
            return bool(self.is_enabled)
        if self.enabled is not None:
            return bool(self.enabled)
        return False

class FirewallRuleRequest(BaseModel):
    action: str = Field(default="ALLOW", description="ALLOW or DENY")
    protocol: str = Field(default="TCP", description="TCP, UDP, or BOTH")
    port: str = Field(..., description="Single port or range (e.g. 8080 or 3000-3005)")
    source: str = Field(default="Any", description="Any or CIDR subnet (e.g. 192.168.1.0/24)")
    comment: Optional[str] = Field(default="", description="Rule description or purpose")
    is_enabled: bool = Field(default=True, description="Rule active state")

class FirewallRuleToggleRequest(BaseModel):
    is_enabled: bool
