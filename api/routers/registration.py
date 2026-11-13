"""
ZclockID Enterprise Management Appliance - Self-Registration & Captive Portal Router
Handles self-service user onboarding, mobile OTP dispatch and verification, organization department management,
and administrator approval queue.
"""

from fastapi import APIRouter, HTTPException, status, Request, BackgroundTasks, Depends
import sqlite3
import time
import re
import secrets
import logging
import requests
import smtplib
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from api.core.config import DB_PATH
from api.core.security import validate_ad_password_complexity
from api.services.system_service import run_cmd, log_audit, get_primary_realm
from api.services.samba_service import provision_user_in_ad
from api.services.radius_service import sync_freeradius_policies
from api.schemas.registration_schema import (
    SelfRegistrationSettingsRequest,
    SelfRegistrationSubmitRequest,
    SelfRegistrationOtpVerifyRequest,
    SelfRegistrationResendOtpRequest,
    SelfRegistrationApprovalAction
)

from api.routers.auth import require_role

logger = logging.getLogger("zclockid.registration")
router = APIRouter(prefix="/api/v1", tags=["Self-Registration & Captive Portal"], dependencies=[Depends(require_role("readonly"))])

def get_self_registration_settings() -> Dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM self_registration_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    primary_realm = get_primary_realm().lower()
    return {
        "id": 1,
        "enabled": 1,
        "require_mobile_otp": 1,
        "auto_approve_with_otp": 1,
        "default_domain": primary_realm,
        "default_group": "Domain Users",
        "default_bandwidth_profile_id": 0,
        "allowed_departments": "Engineering,IT Operations,Finance,Human Resources,Sales & Marketing,Operations",
        "sms_gateway_type": "simulated",
        "sms_gateway_url": "",
        "sms_api_key": "",
        "sms_sender_id": "ZCLOCK",
        "sms_template": "Your ZclockID verification code is {otp}. Valid for 10 minutes.",
        "email_smtp_enabled": 0,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_pass": "",
        "smtp_from": f"no-reply@{primary_realm}",
        "updated_at": time.time()
    }

def dispatch_sms(mobile: str, message: str, settings: dict) -> tuple[bool, str]:
    gw_type = settings.get("sms_gateway_type", "simulated").lower()
    logger.info(f"Dispatching SMS via provider '{gw_type}' to '{mobile}'")

    if gw_type == "simulated":
        logger.info(f"[SMS-SIMULATED] >>> Mobile: {mobile} | Content: {message}")
        log_audit("SMS_DISPATCHED", "system", mobile, "SUCCESS", {"provider": "simulated", "message": message})
        return True, "SMS dispatched via local appliance simulator."

    elif gw_type == "webhook":
        url = settings.get("sms_gateway_url", "").strip()
        if not url:
            return False, "Custom webhook SMS gateway URL is not configured."
        try:
            sender = settings.get("sms_sender_id", "ZCLOCK").strip()
            api_key = settings.get("sms_api_key", "").strip()
            clean_digits = re.sub(r"[^\d]", "", mobile)
            to_10 = clean_digits[-10:] if len(clean_digits) >= 10 else clean_digits

            placeholders = {
                "{to}": urllib.parse.quote(mobile, safe=""),
                "{mobile}": urllib.parse.quote(mobile, safe=""),
                "{to10}": urllib.parse.quote(to_10, safe=""),
                "{to_10}": urllib.parse.quote(to_10, safe=""),
                "{message}": urllib.parse.quote(message, safe=""),
                "{msg}": urllib.parse.quote(message, safe=""),
                "{sender}": urllib.parse.quote(sender, safe=""),
                "{apikey}": urllib.parse.quote(api_key, safe=""),
                "{api_key}": urllib.parse.quote(api_key, safe="")
            }

            has_placeholders = any(ph in url for ph in placeholders)
            is_get_query = has_placeholders or ("?" in url and "=" in url)

            if is_get_query:
                final_url = url
                for ph, val in placeholders.items():
                    if ph in final_url:
                        final_url = final_url.replace(ph, val)
                res = requests.get(final_url, timeout=12)
            else:
                payload = {
                    "to": mobile,
                    "message": message,
                    "sender": sender,
                    "api_key": api_key
                }
                res = requests.post(url, json=payload, timeout=12)

            resp_preview = res.text.strip()[:200]
            upper_resp = resp_preview.upper()
            is_ok = (res.status_code < 300) and not (
                "<STATUS>FAIL</STATUS>" in upper_resp or
                "<STATUS>ERROR</STATUS>" in upper_resp or
                '"STATUS":"ERROR"' in upper_resp
            )
            log_audit("SMS_DISPATCHED", "system", mobile, "SUCCESS" if is_ok else "ERROR", {
                "provider": "webhook",
                "method": "GET" if is_get_query else "POST",
                "status_code": res.status_code,
                "response": resp_preview
            })
            return is_ok, f"HTTP {res.status_code}: {resp_preview}" if resp_preview else f"Webhook responded with HTTP {res.status_code}"
        except Exception as e:
            logger.error(f"Webhook SMS failed: {e}")
            return False, str(e)

    elif gw_type == "twilio":
        url = settings.get("sms_gateway_url", "").strip()
        api_key = settings.get("sms_api_key", "").strip()
        sender = settings.get("sms_sender_id", "").strip()
        if not url or not api_key:
            return False, "Twilio Endpoint URL and Auth Token are required."
        try:
            res = requests.post(url, data={"To": mobile, "From": sender, "Body": message}, auth=tuple(api_key.split(":")), timeout=8)
            return res.status_code in [200, 201], f"Twilio responded with HTTP {res.status_code}"
        except Exception as e:
            return False, str(e)

    elif gw_type == "fast2sms":
        api_key = settings.get("sms_api_key", "").strip()
        if not api_key:
            return False, "Fast2SMS API authorization key required."
        try:
            headers = {"authorization": api_key, "Content-Type": "application/json"}
            payload = {
                "route": "otp",
                "variables_values": message,
                "numbers": mobile.replace("+91", "").replace("+", "").strip()
            }
            res = requests.post("https://www.fast2sms.com/dev/bulkV2", json=payload, headers=headers, timeout=8)
            return res.status_code == 200, "Fast2SMS dispatched"
        except Exception as e:
            return False, str(e)

    elif gw_type == "msg91":
        api_key = settings.get("sms_api_key", "").strip()
        if not api_key:
            return False, "MSG91 authkey required."
        try:
            headers = {"authkey": api_key, "Content-Type": "application/json"}
            payload = {
                "template_id": settings.get("sms_sender_id", ""),
                "mobile": mobile.replace("+", "").strip(),
                "otp": message
            }
            res = requests.post("https://control.msg91.com/api/v5/otp", json=payload, headers=headers, timeout=8)
            return res.status_code == 200, "MSG91 OTP dispatched"
        except Exception as e:
            return False, str(e)

    return True, "Simulated SMS dispatched"

def dispatch_email(to_email: str, subject: str, body: str, settings: dict) -> tuple[bool, str]:
    if not settings.get("email_smtp_enabled"):
        logger.info(f"[EMAIL-SIMULATED] >>> To: {to_email} | Subject: {subject} | Body: {body}")
        log_audit("EMAIL_DISPATCHED", "system", to_email, "SUCCESS", {"provider": "simulated", "subject": subject})
        return True, "Simulated email logged."

    smtp_host = settings.get("smtp_host", "").strip()
    if not smtp_host:
        return False, "SMTP Host is not configured."

    try:
        msg = MIMEMultipart()
        msg["From"] = settings.get("smtp_from", f"no-reply@{get_primary_realm().lower()}")
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        port = int(settings.get("smtp_port", 587))
        user = settings.get("smtp_user", "").strip()
        pwd = settings.get("smtp_pass", "").strip()

        if port == 465:
            server = smtplib.SMTP_SSL(smtp_host, port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_host, port, timeout=10)
            server.starttls()

        if user and pwd:
            server.login(user, pwd)

        server.sendmail(msg["From"], [to_email], msg.as_string())
        server.quit()
        log_audit("EMAIL_DISPATCHED", "system", to_email, "SUCCESS", {"subject": subject})
        return True, "Email dispatched successfully."
    except Exception as e:
        logger.error(f"SMTP dispatch failed: {e}")
        return False, str(e)

@router.get("/public/register/config")
def get_public_registration_config():
    """Returns self-registration availability, verification requirements, and allowed departments for the public portal."""
    settings = get_self_registration_settings()
    primary_realm = get_primary_realm().lower()
    raw_depts = settings.get("allowed_departments") or "Engineering,IT Operations,Finance,Human Resources,Sales & Marketing,Operations"
    dept_list = [d.strip() for d in raw_depts.split(",") if d.strip()][:100]
    return {
        "status": "success",
        "enabled": bool(settings.get("enabled", 1)),
        "require_mobile_otp": bool(settings.get("require_mobile_otp", 1)),
        "auto_approve_with_otp": bool(settings.get("auto_approve_with_otp", 1)),
        "default_domain": settings.get("default_domain") or primary_realm,
        "primary_realm": primary_realm,
        "sms_provider": settings.get("sms_gateway_type", "simulated"),
        "departments": dept_list
    }

@router.post("/public/register/initiate")
@router.post("/registration/submit")
def submit_self_registration(req: SelfRegistrationSubmitRequest, request: Request):
    """Submits a new domain account registration. Dispatches mobile OTP if verification enabled."""
    settings = get_self_registration_settings()
    if not settings.get("enabled", 1):
        raise HTTPException(status_code=403, detail="User self-registration is currently disabled by administrator.")

    clean_user = req.username.strip().lower()
    if not re.match(r"^[a-zA-Z0-9._-]{3,32}$", clean_user):
        raise HTTPException(status_code=400, detail="Username must be 3-32 characters (letters, numbers, dots, dashes).")

    reserved_users = ["admin", "administrator", "root", "guest", "krbtgt", "system", "daemon", "bin", "sys"]
    if clean_user in reserved_users:
        raise HTTPException(status_code=400, detail=f"Username '{clean_user}' is a reserved administrative account name.")

    pwd_ok, pwd_msg = validate_ad_password_complexity(req.password, clean_user, f"{req.given_name} {req.surname}")
    if not pwd_ok:
        raise HTTPException(status_code=400, detail=f"Active Directory Password Complexity: {pwd_msg}")

    raw_depts = settings.get("allowed_departments") or "Engineering,IT Operations,Finance,Human Resources,Sales & Marketing,Operations"
    valid_depts = [d.strip() for d in raw_depts.split(",") if d.strip()]
    req_dept = (req.department or "").strip()
    if req_dept:
        matched = next((d for d in valid_depts if d.lower() == req_dept.lower()), None)
        chosen_dept = matched or req_dept[:64]
    else:
        chosen_dept = valid_depts[0] if valid_depts else "General"

    clean_mobile = re.sub(r"[^\d+]", "", req.mobile.strip())
    if len(clean_mobile.replace("+", "")) < 8:
        raise HTTPException(status_code=400, detail="Please provide a valid mobile number for verification.")

    code, stdout, _ = run_cmd(["samba-tool", "user", "list"], timeout=10)
    if code == 0:
        existing_ad = [u.strip().lower() for u in stdout.splitlines() if u.strip()]
        if clean_user in existing_ad:
            raise HTTPException(status_code=409, detail=f"Username '{clean_user}' is already registered in the domain.")

    client_ip = request.client.host if request.client else "unknown"
    require_otp = bool(settings.get("require_mobile_otp", 1))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM self_registrations WHERE username = ? OR (mobile = ? AND status = 'PENDING_OTP')", (clean_user, clean_mobile))

    if require_otp:
        otp = f"{secrets.randbelow(900000) + 100000}"
        expiry = time.time() + 600

        cursor.execute("""
            INSERT INTO self_registrations (
                username, email, given_name, surname, department, mobile,
                status, ip_address, created_at, otp_code, otp_expires_at, otp_verified, password_hash, notes
            ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_OTP', ?, ?, ?, ?, 0, ?, ?)
        """, (clean_user, req.email.strip(), req.given_name.strip(), req.surname.strip(),
              chosen_dept, clean_mobile, client_ip, time.time(),
              otp, expiry, req.password, req.justification or ""))
        reg_id = cursor.lastrowid
        conn.commit()
        conn.close()

        msg = settings.get("sms_template", "Your ZclockID verification code is {otp}. Valid for 10 minutes.").replace("{otp}", otp).replace("{username}", clean_user)
        sms_ok, sms_msg = dispatch_sms(clean_mobile, msg, settings)
        masked_mobile = clean_mobile[:4] + "*" * (len(clean_mobile) - 7) + clean_mobile[-3:] if len(clean_mobile) > 7 else clean_mobile

        log_audit("REGISTRATION_OTP_DISPATCHED", clean_user, "appliance", "SUCCESS", {"mobile": clean_mobile, "sms_status": sms_msg})

        return {
            "status": "otp_required",
            "registration_id": reg_id,
            "username": clean_user,
            "mobile_masked": masked_mobile,
            "otp_debug": otp if settings.get("sms_gateway_type") == "simulated" else None,
            "message": f"Verification OTP sent to mobile number {masked_mobile}. Please verify to complete activation."
        }
    else:
        cursor.execute("""
            INSERT INTO self_registrations (
                username, email, given_name, surname, department, mobile,
                status, ip_address, created_at, otp_code, otp_expires_at, otp_verified, password_hash, notes
            ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?, ?, NULL, NULL, 0, ?, ?)
        """, (clean_user, req.email.strip(), req.given_name.strip(), req.surname.strip(),
              chosen_dept, clean_mobile, client_ip, time.time(),
              req.password, req.justification or ""))
        reg_id = cursor.lastrowid
        conn.commit()
        conn.close()

        user_msg = f"Hello {req.given_name}, your ZclockID domain registration for '{clean_user}' has been received and is pending administrator review and approval."
        dispatch_sms(clean_mobile, user_msg, settings)
        dispatch_email(req.email.strip(), "ZclockID Registration Received - Pending Approval", user_msg, settings)

        log_audit("REGISTRATION_SUBMITTED_PENDING_APPROVAL", clean_user, "appliance", "SUCCESS", {"mobile": clean_mobile, "email": req.email})

        return {
            "status": "pending_approval",
            "registration_id": reg_id,
            "username": clean_user,
            "message": "Registration received. Your account is pending administrator review and approval."
        }

@router.post("/public/register/verify-otp")
def verify_registration_otp(req: SelfRegistrationOtpVerifyRequest, background_tasks: BackgroundTasks):
    """Verifies mobile OTP code. If valid, automatically provisions and activates user in Samba Active Directory."""
    settings = get_self_registration_settings()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM self_registrations WHERE id = ?", (req.registration_id,))
    reg = cursor.fetchone()

    if not reg:
        conn.close()
        raise HTTPException(status_code=404, detail="Registration request not found.")

    if reg["status"] in ["VERIFIED_AUTO_PROVISIONED", "APPROVED"]:
        conn.close()
        return {"status": "success", "message": "Account has already been verified and provisioned.", "username": reg["username"]}

    if reg["status"] != "PENDING_OTP":
        conn.close()
        raise HTTPException(status_code=400, detail=f"Invalid registration state: {reg['status']}")

    if time.time() > (reg["otp_expires_at"] or 0):
        conn.close()
        raise HTTPException(status_code=400, detail="Verification OTP code has expired. Please request a new code.")

    if req.otp_code.strip() != str(reg["otp_code"]).strip():
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid OTP code. Please check your SMS and try again.")

    username = reg["username"]
    password = reg["password_hash"]
    given_name = reg["given_name"] or ""
    surname = reg["surname"] or ""
    email = reg["email"] or ""
    mobile = reg["mobile"] or ""
    dept = reg["department"] or "Engineering"
    domain = settings.get("default_domain") or get_primary_realm().lower()

    try:
        provision_user_in_ad(
            username=username,
            password=password,
            given_name=given_name,
            surname=surname,
            email=email,
            mobile=mobile,
            department=dept,
            default_domain=domain,
            default_group=settings.get("default_group"),
            default_bandwidth_profile_id=settings.get("default_bandwidth_profile_id", 0)
        )
    except HTTPException:
        conn.close()
        raise
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Failed to provision Active Directory user: {str(e)}")

    cursor.execute("""
        UPDATE self_registrations 
        SET status = 'VERIFIED_AUTO_PROVISIONED', otp_verified = 1, approved_at = ?, approved_by = 'AUTO_OTP', password_hash = 'PROVISIONED'
        WHERE id = ?
    """, (time.time(), req.registration_id))
    conn.commit()
    conn.close()

    welcome_sms = f"Welcome to {domain}! Your corporate domain account '{username}' has been verified and activated. You may now log in to Windows, Wi-Fi, and VPN."
    background_tasks.add_task(dispatch_sms, mobile, welcome_sms, settings)
    background_tasks.add_task(
        dispatch_email,
        email,
        f"Welcome to {domain} - Account Activated",
        f"Hello {given_name},\n\nYour domain account '{username}' has been successfully verified via mobile OTP and created in Active Directory under primary domain '{domain}'.\n\nRegards,\nIdentity & Access Team",
        settings,
    )

    log_audit("USER_SELF_REGISTERED_AUTO_APPROVED", username, "active_directory", "SUCCESS", {"mobile": mobile, "email": email, "domain": domain})

    return {
        "status": "success",
        "username": username,
        "domain": domain,
        "auto_approved": True,
        "message": f"Mobile number verified! Your domain account '{username}@{domain}' is now active."
    }

@router.post("/public/register/resend-otp")
def resend_registration_otp(req: SelfRegistrationResendOtpRequest):
    """Generates and resends a new mobile OTP for an existing unverified registration."""
    settings = get_self_registration_settings()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM self_registrations WHERE id = ? AND status = 'PENDING_OTP'", (req.registration_id,))
    reg = cursor.fetchone()
    if not reg:
        conn.close()
        raise HTTPException(status_code=404, detail="Pending registration request not found.")

    otp = f"{secrets.randbelow(900000) + 100000}"
    expiry = time.time() + 600

    cursor.execute("UPDATE self_registrations SET otp_code = ?, otp_expires_at = ? WHERE id = ?", (otp, expiry, req.registration_id))
    conn.commit()
    conn.close()

    clean_mobile = reg["mobile"]
    msg = settings.get("sms_template", "Your ZclockID verification code is {otp}. Valid for 10 minutes.").replace("{otp}", otp).replace("{username}", reg["username"])
    dispatch_sms(clean_mobile, msg, settings)
    masked_mobile = clean_mobile[:4] + "*" * (len(clean_mobile) - 7) + clean_mobile[-3:] if len(clean_mobile) > 7 else clean_mobile

    return {
        "status": "success",
        "message": f"A new OTP code has been sent to {masked_mobile}.",
        "otp_debug": otp if settings.get("sms_gateway_type") == "simulated" else None
    }

@router.get("/registrations/settings")
def get_registration_settings_endpoint():
    """Returns self-registration and OTP policy settings."""
    settings = get_self_registration_settings()
    return {"status": "success", "settings": settings}

@router.post("/registrations/settings")
def update_registration_settings_endpoint(req: SelfRegistrationSettingsRequest):
    """Updates self-registration, OTP verification, and SMS gateway parameters."""
    raw_depts = req.allowed_departments or ""
    dept_tokens = [d.strip() for d in re.split(r'[,;\n]+', raw_depts) if d.strip()]
    seen_depts = set()
    cleaned_depts = []
    for d in dept_tokens:
        if d.lower() not in seen_depts:
            seen_depts.add(d.lower())
            cleaned_depts.append(d)
    if len(cleaned_depts) > 100:
        raise HTTPException(status_code=400, detail="Organization departments cannot exceed 100 entries.")
    final_depts = ",".join(cleaned_depts) if cleaned_depts else "Engineering,IT Operations,Finance,Human Resources,Sales & Marketing,Operations"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE self_registration_settings SET
            enabled = ?,
            require_mobile_otp = ?,
            auto_approve_with_otp = ?,
            default_domain = ?,
            default_group = ?,
            default_bandwidth_profile_id = ?,
            allowed_departments = ?,
            sms_gateway_type = ?,
            sms_gateway_url = ?,
            sms_api_key = ?,
            sms_sender_id = ?,
            sms_template = ?,
            email_smtp_enabled = ?,
            smtp_host = ?,
            smtp_port = ?,
            smtp_user = ?,
            smtp_pass = ?,
            smtp_from = ?,
            updated_at = ?
        WHERE id = 1
    """, (
        1 if req.enabled else 0,
        1 if req.require_mobile_otp else 0,
        1 if req.auto_approve_with_otp else 0,
        req.default_domain or get_primary_realm().lower(),
        req.default_group or "Domain Users",
        req.default_bandwidth_profile_id or 0,
        final_depts,
        req.sms_gateway_type or "simulated",
        req.sms_gateway_url or "",
        req.sms_api_key or "",
        req.sms_sender_id or "ZCLOCK",
        req.sms_template or "Your ZclockID verification code is {otp}. Valid for 10 minutes.",
        1 if req.email_smtp_enabled else 0,
        req.smtp_host or "",
        req.smtp_port or 587,
        req.smtp_user or "",
        req.smtp_pass or "",
        req.smtp_from or f"no-reply@{get_primary_realm().lower()}",
        time.time()
    ))
    conn.commit()
    conn.close()

    try:
        sync_freeradius_policies()
    except Exception as e:
        logger.warning(f"Failed to sync FreeRADIUS policies after registration settings update: {e}")

    log_audit("REGISTRATION_SETTINGS_UPDATED", "admin", "appliance", "SUCCESS", {
        "enabled": req.enabled,
        "require_mobile_otp": req.require_mobile_otp,
        "sms_provider": req.sms_gateway_type
    })

    return {"status": "success", "message": "Self-registration and OTP policies updated successfully."}

@router.get("/registrations/requests")
def list_registration_requests(status_filter: Optional[str] = "all", limit: Optional[int] = None):
    """Lists self-registration queue entries with status filtering."""
    from api.services.log_retention_service import get_log_retention_settings
    if limit is None or limit <= 0:
        limit = int(get_log_retention_settings().get("self_service_ui_fetch_limit", 500) or 500)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if status_filter and status_filter.lower() != "all":
        cursor.execute("SELECT id, username, email, given_name, surname, department, mobile, status, ip_address, created_at, approved_at, approved_by, notes FROM self_registrations WHERE LOWER(status) = LOWER(?) ORDER BY created_at DESC LIMIT ?", (status_filter, limit))
    else:
        cursor.execute("SELECT id, username, email, given_name, surname, department, mobile, status, ip_address, created_at, approved_at, approved_by, notes FROM self_registrations ORDER BY created_at DESC LIMIT ?", (limit,))

    rows = cursor.fetchall()
    conn.close()

    requests_list = [dict(r) for r in rows]
    return {
        "status": "success",
        "count": len(requests_list),
        "requests": requests_list
    }

@router.post("/registrations/requests/{req_id}/approve")
def approve_registration_request(req_id: int, action: SelfRegistrationApprovalAction):
    """Admin approves a pending registration and provisions user in Active Directory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM self_registrations WHERE id = ?", (req_id,))
    reg = cursor.fetchone()

    if not reg:
        conn.close()
        raise HTTPException(status_code=404, detail="Registration request not found.")

    if reg["status"] in ["APPROVED", "VERIFIED_AUTO_PROVISIONED"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Account is already approved and provisioned.")

    settings = get_self_registration_settings()
    domain = action.target_upn_domain or settings.get("default_domain") or get_primary_realm().lower()
    username = reg["username"]
    password = reg["password_hash"]
    given_name = reg["given_name"] or ""
    surname = reg["surname"] or ""
    email = reg["email"] or ""
    mobile = reg["mobile"] or ""
    dept = reg["department"] or "Engineering"

    if not password or password in ["PROVISIONED", "REJECTED"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Password credential unavailable for deferred provisioning.")

    try:
        provision_user_in_ad(
            username=username,
            password=password,
            given_name=given_name,
            surname=surname,
            email=email,
            mobile=mobile,
            department=dept,
            default_domain=domain,
            default_group=settings.get("default_group"),
            default_bandwidth_profile_id=settings.get("default_bandwidth_profile_id", 0)
        )
    except HTTPException:
        conn.close()
        raise
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Active Directory provisioning failed: {str(e)}")

    cursor.execute("""
        UPDATE self_registrations
        SET status = 'APPROVED', approved_at = ?, approved_by = 'admin', password_hash = 'PROVISIONED', notes = ?
        WHERE id = ?
    """, (time.time(), action.notes or "Approved by administrator", req_id))
    conn.commit()
    conn.close()

    msg = f"Congratulations! Your ZclockID domain account '{username}@{domain}' has been approved by the administrator. You may now log in to Windows, Wi-Fi, and VPN."
    dispatch_sms(mobile, msg, settings)
    dispatch_email(email, "Your ZclockID Domain Account Has Been Approved", f"Hello {given_name},\n\nYour registration request has been approved by the system administrator.\n\nAccount: {username}@{domain}\nDomain: {domain}\n\nRegards,\nIdentity & Access Team", settings)

    log_audit("REGISTRATION_APPROVED_BY_ADMIN", username, "active_directory", "SUCCESS", {"mobile": mobile, "email": email, "domain": domain})

    return {"status": "success", "message": f"User '{username}' approved and provisioned in Active Directory under domain '{domain}'."}

@router.post("/registrations/requests/{req_id}/reject")
def reject_registration_request(req_id: int, action: SelfRegistrationApprovalAction):
    """Admin rejects a pending registration request."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM self_registrations WHERE id = ?", (req_id,))
    reg = cursor.fetchone()

    if not reg:
        conn.close()
        raise HTTPException(status_code=404, detail="Registration request not found.")

    reason = action.notes or "Request rejected by administrator"

    cursor.execute("""
        UPDATE self_registrations
        SET status = 'REJECTED', approved_at = ?, approved_by = 'admin', password_hash = 'REJECTED', notes = ?
        WHERE id = ?
    """, (time.time(), reason, req_id))
    conn.commit()
    conn.close()

    settings = get_self_registration_settings()
    rej_msg = f"Your ZclockID domain registration for '{reg['username']}' was declined by the administrator. Reason: {reason}"
    dispatch_sms(reg["mobile"], rej_msg, settings)
    dispatch_email(reg["email"], "ZclockID Domain Registration Declined", f"Hello {reg['given_name']},\n\nYour domain registration request for username '{reg['username']}' has been declined by the administrator.\n\nReason: {reason}\n\nRegards,\nIdentity & Access Team", settings)

    log_audit("REGISTRATION_REJECTED", reg["username"], "appliance", "SUCCESS", {"reason": reason})

    return {"status": "success", "message": f"Registration request for '{reg['username']}' rejected."}

@router.delete("/registrations/requests/{req_id}")
def delete_registration_request(req_id: int):
    """Deletes a registration record from the queue."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM self_registrations WHERE id = ?", (req_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Registration record deleted."}
