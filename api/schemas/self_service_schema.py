"""
ZclockID Enterprise Management Appliance - Self Service Password Reset Schemas
Pydantic validation models for self-service password changes, email/SMS OTP resets, and administrator settings.
"""

from pydantic import BaseModel, Field
from typing import Optional

class PasswordChangeOldRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=6)

class PasswordResetOtpRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    channel: str = Field(..., pattern="^(email|sms)$")

class PasswordResetVerifyRequest(BaseModel):
    reset_id: int
    username: str
    otp_code: str = Field(..., min_length=4, max_length=10)
    new_password: str = Field(..., min_length=6)

class PasswordResetSettingsUpdate(BaseModel):
    enabled: bool = True
    allow_old_password_reset: bool = True
    allow_email_reset: bool = True
    allow_otp_reset: bool = True
    min_password_length: int = 8
    require_complexity: bool = True
    otp_expiry_minutes: int = 10
    max_daily_attempts: int = 5
    email_smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = ""
    sms_gateway_type: str = "simulated"
    sms_gateway_url: str = ""
    sms_api_key: str = ""
    sms_sender_id: str = "ZCLOCK"
    sms_template: str = "Your ZclockID password reset verification code is {otp}. Valid for 10 minutes."
