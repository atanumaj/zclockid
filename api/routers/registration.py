"""
ZclockID Enterprise Management Appliance - Self-Registration & Captive Portal Router
Handles self-service user onboarding, mobile OTP dispatch and verification, organization department management,
and administrator approval queue.
"""

from fastapi import APIRouter, HTTPException, status, Request, BackgroundTasks, Depends, Body
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
from api.core.security import validate_ad_password_complexity, hash_otp, verify_otp_hash
from api.core.secret_box import (
    encrypt_registration_password,
    decrypt_registration_password,
    DecryptionError,
    check_missing_registration_keys
)
from api.services.system_service import run_cmd, log_audit, get_primary_realm
from api.services.security_service import get_client_ip
from api.services.samba_service import provision_user_in_ad
from api.services.radius_service import sync_freeradius_policies
from api.services.registration_purge import run_registration_purge
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

def get_reg_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA secure_delete=ON")
    return conn

def is_sms_gateway_configured(settings: dict) -> bool:
    """Returns True if a real (non-simulated) external SMS gateway is configured."""
    gw_type = (settings.get("sms_gateway_type") or "simulated").lower().strip()
    if gw_type == "simulated" or not gw_type:
        return False
    if gw_type == "webhook":
        return bool(settings.get("sms_gateway_url", "").strip())
    if gw_type == "twilio":
        return bool(settings.get("sms_gateway_url", "").strip() and settings.get("sms_api_key", "").strip())
    if gw_type in ("fast2sms", "msg91"):
        return bool(settings.get("sms_api_key", "").strip())
    return False


def check_and_record_registration_attempt(mobile: str, client_ip: str, action: str, max_hourly_mobile: int = 3, max_hourly_ip: int = 20):
    """
    Rate-limits registration submit and resend-otp per IP and per mobile number (e.g. 3 SMS per hour).
    Raises HTTP 429 when limits are exceeded.
    """
    cutoff = time.time() - 3600
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registration_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mobile TEXT,
            ip_address TEXT,
            action TEXT,
            timestamp REAL
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reg_attempts ON registration_attempts(timestamp, mobile, ip_address)")

    clean_mob = re.sub(r"[^\d+]", "", (mobile or "").strip())
    if clean_mob and max_hourly_mobile > 0:
        cursor.execute("SELECT COUNT(*) FROM registration_attempts WHERE mobile = ? AND timestamp > ?", (clean_mob, cutoff))
        mob_attempts = cursor.fetchone()[0]
        if mob_attempts >= max_hourly_mobile:
            conn.close()
            log_audit("REGISTRATION_RATE_LIMIT_EXCEEDED", "system", clean_mob, "BLOCKED", {"ip": client_ip, "action": action, "count": mob_attempts, "max": max_hourly_mobile})
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: maximum SMS verification attempts ({max_hourly_mobile} per hour) reached for this mobile number."
            )

    if client_ip and max_hourly_ip > 0:
        cursor.execute("SELECT COUNT(*) FROM registration_attempts WHERE ip_address = ? AND timestamp > ?", (client_ip, cutoff))
        ip_attempts = cursor.fetchone()[0]
        if ip_attempts >= max_hourly_ip:
            conn.close()
            log_audit("REGISTRATION_RATE_LIMIT_EXCEEDED", "system", client_ip, "BLOCKED", {"mobile": clean_mob, "action": action, "count": ip_attempts, "max": max_hourly_ip})
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: maximum registration attempts ({max_hourly_ip} per hour) reached from this IP address."
            )

    cursor.execute(
        "INSERT INTO registration_attempts (mobile, ip_address, action, timestamp) VALUES (?, ?, ?, ?)",
        (clean_mob, client_ip, action, time.time())
    )
    conn.commit()
    conn.close()


def get_self_registration_settings() -> Dict[str, Any]:
    conn = get_reg_db()
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
        "otp_expiry_minutes": 10,
        "registration_approval_ttl_days": 7,
        "approval_purge_tripped": 0,
        "approval_purge_pending_count": 0,
        "approval_purge_detected_at": 0,
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
@router.post("/self-registration/submit")
def submit_self_registration(req: SelfRegistrationSubmitRequest, request: Request):
    """Submits a new domain account registration. Dispatches mobile OTP if verification enabled."""
    settings = get_self_registration_settings()
    if not settings.get("enabled", 1):
        raise HTTPException(status_code=403, detail="User self-registration is currently disabled by administrator.")

    clean_user = req.username.strip().lower()
    if clean_user.startswith("-") or not re.match(r"^[a-zA-Z0-9._-]{3,32}$", clean_user):
        raise HTTPException(status_code=400, detail="Username must be 3-32 characters (letters, numbers, dots, dashes) and cannot start with '-'.")

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

    client_ip = get_client_ip(request)
    require_otp = bool(settings.get("require_mobile_otp", 1))

    if require_otp and not is_sms_gateway_configured(settings):
        raise HTTPException(status_code=503, detail="No verification channel configured.")

    conn = get_reg_db()
    cursor = conn.cursor()

    # Takeover prevention:
    # If the username has a PENDING_APPROVAL row, or a PENDING_OTP row with a different mobile -> 409
    cursor.execute("""
        SELECT id, mobile, status FROM self_registrations
        WHERE username = ? AND status IN ('PENDING_APPROVAL', 'PENDING_OTP')
    """, (clean_user,))
    active_rows = cursor.fetchall()
    for row in active_rows:
        r_mobile, r_status = row[1], row[2]
        if r_status == 'PENDING_APPROVAL':
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A registration for this username is already in progress"
            )
        if r_status == 'PENDING_OTP' and r_mobile != clean_mobile:
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A registration for this username is already in progress"
            )

    # Carry failed_attempts over when the same username or mobile resubmits (last 24 hours only)
    cutoff_24h = time.time() - 86400
    cursor.execute("""
        SELECT MAX(failed_attempts), status FROM self_registrations 
        WHERE (username = ? OR mobile = ?) AND created_at > ?
    """, (clean_user, clean_mobile, cutoff_24h))
    prev_row = cursor.fetchone()
    carried_failed = int(prev_row[0] or 0) if prev_row and prev_row[0] is not None else 0

    if carried_failed >= 5:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Too many failed verification attempts. This registration request has been locked. Please contact your administrator."
        )

    # Rate limiting: 3 SMS per hour per mobile, 20 per IP
    if require_otp:
        check_and_record_registration_attempt(clean_mobile, client_ip, "submit", max_hourly_mobile=3, max_hourly_ip=20)

    # Only delete unverified attempt from the SAME user with the SAME mobile, or old terminal stubs (never delete active PENDING_APPROVAL)
    cursor.execute("""
        DELETE FROM self_registrations 
        WHERE (status = 'PENDING_OTP' AND username = ? AND mobile = ?)
           OR (username = ? AND status IN ('EXPIRED_OTP', 'EXPIRED_APPROVAL', 'REJECTED', 'LOCKED', 'ERROR_REREGISTER'))
    """, (clean_user, clean_mobile, clean_user))

    # Resubmission within 30 days of a rejection gets notes="[PREVIOUSLY REJECTED <date>]"
    cutoff_30d = time.time() - (30 * 86400)
    cursor.execute("""
        SELECT approved_at FROM self_registrations
        WHERE username = ? AND status = 'REJECTED' AND approved_at > ?
        ORDER BY approved_at DESC LIMIT 1
    """, (clean_user, cutoff_30d))
    prev_rej = cursor.fetchone()
    prev_rej_prefix = ""
    if prev_rej and prev_rej[0]:
        rej_date = time.strftime("%Y-%m-%d", time.gmtime(prev_rej[0]))
        prev_rej_prefix = f"[PREVIOUSLY REJECTED {rej_date}] "

    user_notes = (req.justification or "").strip()
    if prev_rej_prefix:
        user_notes = f"{prev_rej_prefix}{user_notes}".strip()

    otp_mins = int(settings.get("otp_expiry_minutes", 10) or 10)
    otp_mins = max(1, min(30, otp_mins))
    now_ts = time.time()

    if require_otp:
        otp = f"{secrets.randbelow(900000) + 100000}"
        otp_hashed = hash_otp(otp)
        expiry = now_ts + (otp_mins * 60)

        cursor.execute("""
            INSERT INTO self_registrations (
                username, email, given_name, surname, department, mobile,
                status, ip_address, created_at, otp_code, otp_expires_at, otp_verified,
                password_hash, password_enc, notes, failed_attempts
            ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_OTP', ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
        """, (clean_user, req.email.strip(), req.given_name.strip(), req.surname.strip(),
              chosen_dept, clean_mobile, client_ip, now_ts,
              otp_hashed, expiry, user_notes, carried_failed))
        reg_id = cursor.lastrowid

        enc_pw = encrypt_registration_password(reg_id, clean_user, req.password)
        cursor.execute("UPDATE self_registrations SET password_enc = ? WHERE id = ?", (enc_pw, reg_id))
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
            "message": f"Verification OTP sent to mobile number {masked_mobile}. Please verify to complete activation."
        }
    else:
        cursor.execute("""
            INSERT INTO self_registrations (
                username, email, given_name, surname, department, mobile,
                status, ip_address, created_at, otp_code, otp_expires_at, otp_verified,
                password_hash, password_enc, notes, failed_attempts
            ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?, ?, NULL, NULL, 0, NULL, NULL, ?, 0)
        """, (clean_user, req.email.strip(), req.given_name.strip(), req.surname.strip(),
              chosen_dept, clean_mobile, client_ip, now_ts,
              user_notes))
        reg_id = cursor.lastrowid

        enc_pw = encrypt_registration_password(reg_id, clean_user, req.password)
        cursor.execute("UPDATE self_registrations SET password_enc = ? WHERE id = ?", (enc_pw, reg_id))
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
@router.post("/self-registration/verify-otp")
def verify_registration_otp(req: SelfRegistrationOtpVerifyRequest, background_tasks: BackgroundTasks):
    """Verifies mobile OTP code. If valid, automatically provisions and activates user in Samba Active Directory."""
    settings = get_self_registration_settings()
    conn = get_reg_db()
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

    if reg["status"] == "LOCKED":
        conn.close()
        raise HTTPException(status_code=400, detail="This registration request has been locked due to too many failed attempts.")

    if reg["status"] != "PENDING_OTP":
        conn.close()
        raise HTTPException(status_code=400, detail=f"Invalid registration state: {reg['status']}")

    if time.time() > (reg["otp_expires_at"] or 0):
        conn.close()
        raise HTTPException(status_code=400, detail="Verification OTP code has expired. Please request a new code.")

    # Validate OTP hash
    clean_otp = req.otp_code.strip()
    stored_hash = str(reg["otp_code"]).strip() if reg["otp_code"] else ""
    if not verify_otp_hash(clean_otp, stored_hash):
        failed_attempts = int(reg["failed_attempts"] or 0) + 1
        new_status = "LOCKED" if failed_attempts >= 5 else "PENDING_OTP"
        if failed_attempts >= 5:
            cursor.execute("UPDATE self_registrations SET failed_attempts = ?, status = 'LOCKED', password_enc = NULL, otp_code = NULL WHERE id = ?", (failed_attempts, req.registration_id))
        else:
            cursor.execute("UPDATE self_registrations SET failed_attempts = ?, status = ? WHERE id = ?", (failed_attempts, new_status, req.registration_id))
        conn.commit()
        conn.close()

        if failed_attempts >= 5:
            log_audit("REGISTRATION_LOCKED", reg["username"], "appliance", "LOCKED", {"reg_id": req.registration_id, "attempts": failed_attempts})
            raise HTTPException(status_code=400, detail="Too many failed verification attempts. This registration request has been locked.")
        else:
            raise HTTPException(status_code=400, detail=f"Invalid OTP code ({5 - failed_attempts} attempts remaining). Please check your SMS and try again.")

    username = reg["username"]
    given_name = reg["given_name"] or ""
    surname = reg["surname"] or ""
    email = reg["email"] or ""
    mobile = reg["mobile"] or ""
    dept = reg["department"] or "Engineering"
    domain = settings.get("default_domain") or get_primary_realm().lower()

    now_verified = time.time()
    auto_approve = bool(settings.get("auto_approve_with_otp", 1))

    if not auto_approve:
        cursor.execute("""
            UPDATE self_registrations 
            SET status = 'PENDING_APPROVAL', otp_verified = 1, otp_verified_at = ?, otp_code = NULL
            WHERE id = ?
        """, (now_verified, req.registration_id))
        conn.commit()
        conn.close()

        log_audit("REGISTRATION_OTP_VERIFIED_PENDING_APPROVAL", username, "appliance", "SUCCESS", {"mobile": mobile, "email": email, "domain": domain})
        return {
            "status": "pending_approval",
            "username": username,
            "domain": domain,
            "auto_approved": False,
            "message": "Mobile number verified! Your registration is now pending administrator review and approval."
        }

    # Decrypt password via SecretBox for auto-provisioning
    try:
        if not reg["password_enc"]:
            raise DecryptionError("Missing encrypted password payload")
        password = decrypt_registration_password(reg["id"], username, reg["password_enc"])
    except DecryptionError as e:
        cursor.execute("UPDATE self_registrations SET status = 'ERROR_REREGISTER', password_enc = NULL WHERE id = ?", (req.registration_id,))
        conn.commit()
        conn.close()
        log_audit("REGISTRATION_DECRYPT_FAILED", "system", username, "ERROR", {
            "reg_id": req.registration_id,
            "error": str(e)
        })
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration decryption failed. Please register again."
        )

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
        SET status = 'VERIFIED_AUTO_PROVISIONED', otp_verified = 1, otp_verified_at = ?,
            approved_at = ?, approved_by = 'AUTO_OTP', password_enc = NULL, password_hash = NULL
        WHERE id = ?
    """, (now_verified, now_verified, req.registration_id))
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
@router.post("/self-registration/resend-otp")
def resend_registration_otp(req: SelfRegistrationResendOtpRequest, request: Request):
    """Generates and resends a new mobile OTP for an existing unverified registration."""
    settings = get_self_registration_settings()
    if not is_sms_gateway_configured(settings):
        raise HTTPException(status_code=503, detail="No verification channel configured.")

    client_ip = get_client_ip(request)

    conn = get_reg_db()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM self_registrations WHERE id = ?", (req.registration_id,))
    reg = cursor.fetchone()
    if not reg:
        conn.close()
        raise HTTPException(status_code=404, detail="Pending registration request not found.")

    if reg["status"] == "LOCKED" or int(reg["failed_attempts"] or 0) >= 5:
        conn.close()
        raise HTTPException(status_code=400, detail="This registration request has been locked due to too many failed attempts.")

    if reg["status"] != "PENDING_OTP":
        conn.close()
        raise HTTPException(status_code=400, detail=f"Cannot resend OTP for registration with status '{reg['status']}'.")

    clean_mobile = reg["mobile"]

    # Rate limit check: 3 SMS per hour
    check_and_record_registration_attempt(clean_mobile, client_ip, "resend-otp", max_hourly_mobile=3, max_hourly_ip=20)

    otp_mins = int(settings.get("otp_expiry_minutes", 10) or 10)
    otp_mins = max(1, min(30, otp_mins))

    otp = f"{secrets.randbelow(900000) + 100000}"
    otp_hashed = hash_otp(otp)
    expiry = time.time() + (otp_mins * 60)

    cursor.execute("UPDATE self_registrations SET otp_code = ?, otp_expires_at = ? WHERE id = ?", (otp_hashed, expiry, req.registration_id))
    conn.commit()
    conn.close()

    msg = settings.get("sms_template", "Your ZclockID verification code is {otp}. Valid for 10 minutes.").replace("{otp}", otp).replace("{username}", reg["username"])
    dispatch_sms(clean_mobile, msg, settings)
    masked_mobile = clean_mobile[:4] + "*" * (len(clean_mobile) - 7) + clean_mobile[-3:] if len(clean_mobile) > 7 else clean_mobile

    return {
        "status": "success",
        "message": f"A new OTP code has been sent to {masked_mobile}."
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

    otp_mins = req.otp_expiry_minutes if req.otp_expiry_minutes is not None else 10
    otp_mins = max(1, min(30, int(otp_mins)))
    appr_days = req.registration_approval_ttl_days if req.registration_approval_ttl_days is not None else 7
    appr_days = max(1, min(90, int(appr_days)))

    conn = get_reg_db()
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
            otp_expiry_minutes = ?,
            registration_approval_ttl_days = ?,
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
        otp_mins,
        appr_days,
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
        "sms_provider": req.sms_gateway_type,
        "otp_expiry_minutes": otp_mins,
        "registration_approval_ttl_days": appr_days
    })

    return {"status": "success", "message": "Self-registration and OTP policies updated successfully."}

@router.get("/registrations/requests")
def list_registration_requests(status_filter: Optional[str] = "all", limit: Optional[int] = None):
    """Lists self-registration queue entries with status filtering, badge detection, and key alerts."""
    from api.services.log_retention_service import get_log_retention_settings
    if limit is None or limit <= 0:
        limit = int(get_log_retention_settings().get("self_service_ui_fetch_limit", 500) or 500)
    conn = get_reg_db()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if status_filter and status_filter.lower() != "all":
        cursor.execute("SELECT id, username, email, given_name, surname, department, mobile, status, ip_address, created_at, approved_at, approved_by, notes FROM self_registrations WHERE LOWER(status) = LOWER(?) ORDER BY created_at DESC LIMIT ?", (status_filter, limit))
    else:
        cursor.execute("SELECT id, username, email, given_name, surname, department, mobile, status, ip_address, created_at, approved_at, approved_by, notes FROM self_registrations ORDER BY created_at DESC LIMIT ?", (limit,))

    rows = cursor.fetchall()
    conn.close()

    requests_list = []
    for r in rows:
        d = dict(r)
        d["previously_rejected"] = bool(d.get("notes") and "[PREVIOUSLY REJECTED" in d["notes"])
        requests_list.append(d)

    missing_keys = check_missing_registration_keys()
    missing_banner = f"{missing_keys} pending registrations can't be decrypted and will expire" if missing_keys > 0 else None

    settings = get_self_registration_settings()
    clock_guard_tripped = bool(settings.get("approval_purge_tripped", 0))
    pending_expired_count = int(settings.get("approval_purge_pending_count", 0) or 0)

    return {
        "status": "success",
        "count": len(requests_list),
        "requests": requests_list,
        "missing_keys_warning": missing_banner,
        "clock_guard_tripped": clock_guard_tripped,
        "pending_expired_count": pending_expired_count
    }

@router.post("/registrations/approval-purge/force")
def force_approval_purge_endpoint(user: dict = Depends(require_role("fulladmin"))):
    """Forces execution of expired registration approvals even if clock guard tripped (requires fulladmin)."""
    res = run_registration_purge(force_clock_guard=True)
    username = user.get("username") or user.get("sub", "admin")
    log_audit("REGISTRATION_APPROVAL_PURGE_FORCED", username, "appliance", "SUCCESS", res)
    return {"status": "success", "result": res}

@router.post("/registrations/requests/{req_id}/approve")
def approve_registration_request(
    req_id: int,
    action: Optional[SelfRegistrationApprovalAction] = Body(default=None),
    current_user: dict = Depends(require_role("operator", "fulladmin"))
):
    """Admin approves a pending registration and provisions user in Active Directory."""
    actor = current_user.get("username") if current_user else "admin"
    if action is None:
        action = SelfRegistrationApprovalAction()
    conn = get_reg_db()
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
    given_name = reg["given_name"] or ""
    surname = reg["surname"] or ""
    email = reg["email"] or ""
    mobile = reg["mobile"] or ""
    dept = reg["department"] or "Engineering"

    # Decrypt password via SecretBox
    try:
        if not reg["password_enc"]:
            raise DecryptionError("Missing encrypted password payload")
        password = decrypt_registration_password(reg["id"], username, reg["password_enc"])
    except DecryptionError as e:
        cursor.execute("UPDATE self_registrations SET status = 'ERROR_REREGISTER', password_enc = NULL WHERE id = ?", (req_id,))
        conn.commit()
        conn.close()
        log_audit("REGISTRATION_DECRYPT_FAILED", "system", username, "ERROR", {
            "reg_id": req_id,
            "error": str(e)
        })
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration decryption failed. User cannot be provisioned."
        )

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
        SET status = 'APPROVED', approved_at = ?, approved_by = ?, password_enc = NULL, password_hash = NULL, notes = ?
        WHERE id = ?
    """, (time.time(), actor, action.notes or "Approved by administrator", req_id))
    conn.commit()
    conn.close()

    msg = f"Congratulations! Your ZclockID domain account '{username}@{domain}' has been approved by the administrator. You may now log in to Windows, Wi-Fi, and VPN."
    dispatch_sms(mobile, msg, settings)
    dispatch_email(email, "Your ZclockID Domain Account Has Been Approved", f"Hello {given_name},\n\nYour registration request has been approved by the system administrator.\n\nAccount: {username}@{domain}\nDomain: {domain}\n\nRegards,\nIdentity & Access Team", settings)

    log_audit("REGISTRATION_APPROVED_BY_ADMIN", actor, username, "SUCCESS", {"mobile": mobile, "email": email, "domain": domain})

    return {"status": "success", "message": f"User '{username}' approved and provisioned in Active Directory under domain '{domain}'."}

@router.post("/registrations/requests/{req_id}/reject")
def reject_registration_request(
    req_id: int,
    action: Optional[SelfRegistrationApprovalAction] = Body(default=None),
    current_user: dict = Depends(require_role("operator", "fulladmin"))
):
    """Admin rejects a pending registration request."""
    actor = current_user.get("username") if current_user else "admin"
    if action is None:
        action = SelfRegistrationApprovalAction()
    conn = get_reg_db()
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
        SET status = 'REJECTED', approved_at = ?, approved_by = ?, password_enc = NULL, password_hash = NULL, notes = ?
        WHERE id = ?
    """, (time.time(), actor, reason, req_id))
    conn.commit()
    conn.close()

    settings = get_self_registration_settings()
    rej_msg = f"Your ZclockID domain registration for '{reg['username']}' was declined by the administrator. Reason: {reason}"
    dispatch_sms(reg["mobile"], rej_msg, settings)
    dispatch_email(reg["email"], "ZclockID Domain Registration Declined", f"Hello {reg['given_name']},\n\nYour domain registration request for username '{reg['username']}' has been declined by the administrator.\n\nReason: {reason}\n\nRegards,\nIdentity & Access Team", settings)

    log_audit("REGISTRATION_REJECTED", actor, reg["username"], "SUCCESS", {"reason": reason})

    return {"status": "success", "message": f"Registration request for '{reg['username']}' rejected."}

@router.delete("/registrations/requests/{req_id}")
def delete_registration_request(req_id: int):
    """Deletes a registration record from the queue."""
    conn = get_reg_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM self_registrations WHERE id = ?", (req_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Registration record deleted."}
