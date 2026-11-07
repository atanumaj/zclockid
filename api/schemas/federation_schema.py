"""
ZclockID Enterprise Identity Federation & Keycloak SSO Schemas
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class KeycloakFederationConfigResponse(BaseModel):
    realm: str = Field(..., example="EXAMPLE.COM")
    base_dn: str = Field(..., example="DC=example,DC=com")
    users_dn: str = Field(..., example="CN=Users,DC=example,DC=com")
    groups_dn: str = Field(..., example="CN=Users,DC=example,DC=com")
    dc_host: str = Field(..., example="dc1")
    dc_fqdn: str = Field(..., example="dc1.example.com")
    dc_ip: str = Field(..., example="192.168.1.41")
    ldap_url: str = Field(..., example="ldap://192.168.1.41:389")
    ldaps_url: str = Field(..., example="ldaps://192.168.1.41:636")
    vendor: str = "Active Directory"
    username_ldap_attribute: str = "sAMAccountName"
    rdn_ldap_attribute: str = "cn"
    uuid_ldap_attribute: str = "objectGUID"
    user_object_classes: str = "person, organizationalPerson, user"
    search_filter: str = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    kerberos_realm: str = Field(..., example="EXAMPLE.COM")
    server_principal: str = Field(..., example="HTTP/sso.example.com@EXAMPLE.COM")
    keytab_exists: bool = False
    keytab_path: str = "/etc/zclockid/keycloak.keytab"
    keytab_size_bytes: Optional[int] = 0
    keytab_updated_at: Optional[float] = None

class KeytabGenerateRequest(BaseModel):
    service_account: str = Field("svc-keycloak", example="svc-keycloak")
    spn: str = Field(..., example="HTTP/sso.example.com")

class TestLdapConnectionRequest(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = 389
    use_ssl: bool = False
    bind_dn: Optional[str] = None
    bind_password: Optional[str] = None
