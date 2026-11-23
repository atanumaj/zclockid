"""
ZclockID Enterprise Management Appliance - User, Group & Computer Schemas
Pydantic input and output validation models for Active Directory identity objects.
"""

from pydantic import BaseModel, Field
from typing import Optional, List

class UserCreateRequest(BaseModel):
    username: str = Field(..., example="john.doe")
    password: str = Field(..., min_length=8, example="<choose-a-strong-password>")
    given_name: Optional[str] = Field(None, example="John")
    surname: Optional[str] = Field(None, example="Doe")
    email: Optional[str] = Field(None, example="john.doe@corp.example.com")
    mobile: Optional[str] = Field(None, example="+919876543210")
    department: Optional[str] = None
    target_group: Optional[str] = "Domain Users"
    groups: Optional[List[str]] = Field(default_factory=list)
    bandwidth_profile_id: Optional[int] = None
    password_never_expires: Optional[bool] = False

class UserUpdateRequest(BaseModel):
    given_name: Optional[str] = None
    surname: Optional[str] = None
    email: Optional[str] = None
    mobile: Optional[str] = None
    department: Optional[str] = None
    user_principal_name: Optional[str] = None
    bandwidth_profile_id: Optional[int] = None
    new_password: Optional[str] = None
    is_disabled: Optional[bool] = None
    groups: Optional[List[str]] = None
    password_never_expires: Optional[bool] = None

class UserPasswordReset(BaseModel):
    new_password: str = Field(..., min_length=8, example="NewSecureP@ss2026!")
    must_change_at_next_logon: bool = False

class UserUpnUpdateRequest(BaseModel):
    user_principal_name: str

class GroupCreateRequest(BaseModel):
    group_name: str = Field(..., example="SG-IT-Admins")
    description: Optional[str] = None
    bandwidth_profile_id: Optional[int] = None

class GroupUpdateRequest(BaseModel):
    description: Optional[str] = None
    bandwidth_profile_id: Optional[int] = None

class GroupMemberActionRequest(BaseModel):
    username: str = Field(..., example="john.doe")


