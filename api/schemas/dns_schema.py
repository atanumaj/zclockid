"""
ZclockID Enterprise Management Appliance - Encrypted DNS (BIND9 DLZ & DoH) Schemas
Pydantic input and output validation models for DNS Zones, Records, Forwarders, and DoH tests.
"""

from pydantic import BaseModel, Field
from typing import Optional, List

class DnsRecordRequest(BaseModel):
    zone: str = Field(..., example="example.com")
    record_name: str = Field(..., example="web")
    record_type: str = Field("A", pattern="^(A|AAAA|CNAME|TXT|SRV|MX|PTR|NS|SOA|CAA)$")
    record_data: str = Field(..., example="192.0.2.1")
    port: Optional[int] = Field(None, example=88)
    priority: Optional[int] = Field(0, example=0)
    weight: Optional[int] = Field(100, example=100)
    ttl: Optional[int] = Field(900, example=900)

class DnsRecordUpdateRequest(BaseModel):
    zone: str = Field(..., example="example.com")
    record_name: str = Field(..., example="web")
    record_type: str = Field("A", pattern="^(A|AAAA|CNAME|TXT|SRV|MX|PTR|NS|SOA|CAA)$")
    old_data: str = Field(..., example="192.0.2.1")
    new_data: str = Field(..., example="192.0.2.2")
    port: Optional[int] = Field(None, example=88)
    priority: Optional[int] = Field(0, example=0)
    weight: Optional[int] = Field(100, example=100)
    ttl: Optional[int] = Field(900, example=900)

class DnsForwardersRequest(BaseModel):
    forwarders: List[str] = Field(..., example=["1.1.1.1", "8.8.8.8"])
    policy: Optional[str] = Field("first", pattern="^(first|only)$")

class DnsZoneCreateRequest(BaseModel):
    zone_name: str = Field(..., example="example.com")

class DohTestRequest(BaseModel):
    query_name: Optional[str] = "example.com"
    query_type: Optional[str] = "A"
    qname: Optional[str] = None
    rtype: Optional[str] = None

class HostOverrideRequest(BaseModel):
    fqdn: str = Field(..., example="vpn.example.com")
    record_type: str = Field("A", pattern="^(A|AAAA|CNAME|TXT)$")
    target: str = Field(..., example="192.0.2.5")
    description: Optional[str] = Field("", example="Branch Office Gateway")

class DomainForwarderRequest(BaseModel):
    domain: str = Field(..., example="organization.net")
    forwarders: List[str] = Field(..., example=["192.0.2.30"])
    policy: Optional[str] = Field("only", pattern="^(only|first)$")
    description: Optional[str] = Field("", example="Remote Office DNS")

class DnsCacheFlushRequest(BaseModel):
    hostname: Optional[str] = Field(None, example="example.com")

