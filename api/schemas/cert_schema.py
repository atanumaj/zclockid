"""
ZclockID SSL/TLS Certificate Management Schemas
"""

from typing import Optional, List
from pydantic import BaseModel, Field

class SelfSignedCertRequest(BaseModel):
    common_name: Optional[str] = Field(None, example="dc1.example.com")
    san_list: List[str] = Field(default_factory=lambda: ["192.0.2.1", "dc1.example.com", "dc1"])
    validity_days: int = Field(365, ge=30, le=3650, example=365)
    organization: Optional[str] = Field("Example Organization", example="Example Organization")

class CertUploadRequest(BaseModel):
    cert_pem: str = Field(..., description="Server Certificate in PEM format (-----BEGIN CERTIFICATE-----)")
    key_pem: str = Field(..., description="Private Key in PEM format (-----BEGIN RSA PRIVATE KEY----- or -----BEGIN PRIVATE KEY-----)")
    chain_pem: Optional[str] = Field(None, description="Optional Intermediate CA chain in PEM format")

class CsrGenerateRequest(BaseModel):
    common_name: str = Field(..., example="dc1.example.com")
    organization: str = Field(..., example="Example Organization")
    organizational_unit: Optional[str] = Field("IT Infrastructure", example="IT Infrastructure")
    city: str = Field(..., example="New York")
    state: str = Field(..., example="NY")
    country: str = Field(..., min_length=2, max_length=2, example="US")
    san_list: List[str] = Field(default_factory=list, example=["192.0.2.1", "dc1.example.com"])

class ActiveCertDetailsResponse(BaseModel):
    subject: str
    issuer: str
    valid_from: str
    valid_to: str
    days_remaining: int
    san_list: List[str]
    signature_algorithm: str
    serial_number: str
    is_self_signed: bool
    status: str  # VALID, EXPIRING_SOON, EXPIRED

