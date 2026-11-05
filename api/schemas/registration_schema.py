"""
ZclockID Enterprise Management Appliance - Self-Registration & Guest Portal Schemas
Pydantic input and output validation models for guest onboarding, SMS OTP verification, and approvals.
"""

from pydantic import BaseModel, Field
from typing import Optional

class SelfRegistrationSettingsRequest(BaseModel):
    enabled: bool = True
    require_mobile_otp: bool = True
    auto_approve_with_otp: bool = True
    default_domain: Optional[str] = "inet.net"
    default_group: Optional[str] = "Domain Users"
    default_bandwidth_profile_id: Optional[int] = 0
    allowed_departments: Optional[str] = "Engineering,IT Operations,Finance,Human Resources,Sales & Marketing,Operations"
    sms_gateway_type: Optional[str] = "simulated"
    sms_gateway_url: Optional[str] = ""
    sms_api_key: Optional[str] = ""
    sms_sender_id: Optional[str] = "ZCLOCK"
    sms_template: Optional[str] = "Your ZclockID verification code is {otp}. Valid for 10 minutes."
    email_smtp_enabled: Optional[bool] = False
    smtp_host: Optional[str] = ""
    smtp_port: Optional[int] = 587
    smtp_user: Optional[str] = ""
    smtp_pass: Optional[str] = ""
    smtp_from: Optional[str] = "no-reply@inet.net"

class SelfRegistrationSubmitRequest(BaseModel):
    username: str
    password: str
    given_name: str
    surname: str
    email: str
    mobile: str
    department: Optional[str] = "Engineering"
    job_title: Optional[str] = ""
    justification: Optional[str] = ""

class SelfRegistrationOtpVerifyRequest(BaseModel):
    registration_id: int
    otp_code: str

class SelfRegistrationResendOtpRequest(BaseModel):
    registration_id: int

class SelfRegistrationApprovalAction(BaseModel):
    notes: Optional[str] = ""
    target_upn_domain: Optional[str] = None
