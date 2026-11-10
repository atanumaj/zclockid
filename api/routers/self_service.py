"""
ZclockID Enterprise Management Appliance - Self Services & Password Reset Router
Provides Self-Service Password Reset (SSPR) via Old Password, Email OTP, and SMS OTP,
as well as audit logging, month filtering, search, pagination, and CSV log exports.
"""

import os
import re
import csv
import io
import time
import json
import secrets
import sqlite3
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse

from api.core.config import DB_PATH, SAMBA_LDB_PATH
from api.core.security import get_ad_creds, validate_ad_password_complexity
from api.services.system_service import run_cmd, log_audit, get_primary_realm
from api.routers.registration import dispatch_sms, dispatch_email
from api.schemas.self_service_schema import (
    PasswordChangeOldRequest,
    PasswordResetOtpRequest,
    PasswordResetVerifyRequest,
    PasswordResetSettingsUpdate
)

logger = logging.getLogger("zclockid.self_service")
router = APIRouter(prefix="/api/v1/self-service", tags=["Self Services & Password Reset"])


def get_sspr_settings() -> Dict[str, Any]:
    """Retrieves Self Service Password Reset configuration."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM self_service_password_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)

    # Defaults
    return {
        "id": 1,
        "enabled": 1,
        "allow_old_password_reset": 1,
        "allow_email_reset": 1,
        "allow_otp_reset": 1,
        "min_password_length": 8,
        "require_complexity": 1,
        "otp_expiry_minutes": 10,
        "max_daily_attempts": 5,
        "email_smtp_enabled": 0,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_pass": "",
        "smtp_from": "",
        "sms_gateway_type": "simulated",
        "sms_gateway_url": "",
        "sms_api_key": "",
        "sms_sender_id": "ZCLOCK",
        "sms_template": "Your ZclockID password reset verification code is {otp}. Valid for 10 minutes.",
        "updated_at": time.time()
    }


def lookup_ad_user(username: str) -> Dict[str, Any]:
    """Searches Active Directory (Samba LDB) for user account and contact attributes."""
    clean_user = username.strip()
    if not clean_user:
        return {"found": False}

    # Query by sAMAccountName, userPrincipalName, or mail
    query = f"(&(objectClass=user)(!(objectClass=computer))(|(sAMAccountName={clean_user})(userPrincipalName={clean_user})(mail={clean_user})))"
    code, stdout, stderr = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        query,
        "sAMAccountName", "mail", "mobile", "telephoneNumber", "userPrincipalName", "userAccountControl"
    ], timeout=10)

    if code != 0 or "dn: " not in stdout:
        return {"found": False}

    account_name = clean_user
    email = None
    mobile = None
    uac = 512

    for line in stdout.splitlines():
        line = line.strip()
        if line.lower().startswith("samaccountname:"):
            account_name = line.split(":", 1)[1].strip()
        elif line.lower().startswith("mail:"):
            email = line.split(":", 1)[1].strip()
        elif line.lower().startswith("mobile:"):
            mobile = line.split(":", 1)[1].strip()
        elif line.lower().startswith("telephonenumber:") and not mobile:
            mobile = line.split(":", 1)[1].strip()
        elif line.lower().startswith("useraccountcontrol:"):
            try:
                uac = int(line.split(":", 1)[1].strip())
            except:
                pass

    is_disabled = bool(uac & 2)

    return {
        "found": True,
        "username": account_name,
        "email": email,
        "mobile": mobile,
        "is_disabled": is_disabled
    }


def mask_email(email: str) -> str:
    if not email or "@" not in email:
        return ""
    user, domain = email.split("@", 1)
    if len(user) <= 2:
        masked_user = user[0] + "*"
    else:
        masked_user = user[0] + ("*" * (len(user) - 2)) + user[-1]
    return f"{masked_user}@{domain}"


def mask_phone(phone: str) -> str:
    if not phone:
        return ""
    clean = re.sub(r"[^\d+]", "", phone)
    if len(clean) <= 5:
        return clean
    return clean[:3] + ("*" * (len(clean) - 6)) + clean[-3:]


# ==================== PUBLIC PORTAL ENDPOINTS ====================

@router.get("/password/config")
def get_public_password_config():
    """Returns SSPR public policy, supported methods, and primary domain name."""
    settings = get_sspr_settings()
    primary_realm = get_primary_realm()

    return {
        "status": "success",
        "enabled": bool(settings.get("enabled", 1)),
        "allow_old_password_reset": bool(settings.get("allow_old_password_reset", 1)),
        "allow_email_reset": bool(settings.get("allow_email_reset", 1)),
        "allow_otp_reset": bool(settings.get("allow_otp_reset", 1)),
        "min_password_length": int(settings.get("min_password_length", 8)),
        "require_complexity": bool(settings.get("require_complexity", 1)),
        "primary_domain": primary_realm,
        "support_notice": "If your phone number and email are not registered, please contact your Domain Administrator."
    }


@router.post("/password/change-with-old")
def change_password_with_old(req: PasswordChangeOldRequest, request: Request):
    """Changes password when user knows their current Active Directory password."""
    settings = get_sspr_settings()
    if not settings.get("enabled", 1):
        raise HTTPException(status_code=403, detail="Self Service Password Reset is currently disabled by administrator.")
    if not settings.get("allow_old_password_reset", 1):
        raise HTTPException(status_code=403, detail="Direct password change using current password is not permitted.")

    client_ip = request.client.host if request.client else "127.0.0.1"
    clean_user = req.username.strip()

    # Look up user to resolve sAMAccountName if UPN or email entered
    user_info = lookup_ad_user(clean_user)
    if user_info.get("found"):
        clean_user = user_info["username"]

    # Check password complexity if required
    min_len = int(settings.get("min_password_length", 8))
    if len(req.new_password) < min_len:
        raise HTTPException(status_code=400, detail=f"New password must be at least {min_len} characters long.")

    if settings.get("require_complexity", 1):
        is_valid, msg = validate_ad_password_complexity(req.new_password)
        if not is_valid:
            raise HTTPException(status_code=400, detail=msg)

    # Use native Samba user password tool with user's current credentials over localhost SAMR
    # samba-tool user password -U <username> --password=<old> --newpassword=<new> --ipaddress=127.0.0.1 --use-kerberos=off
    cmd = [
        "samba-tool", "user", "password",
        f"-U{clean_user}",
        f"--password={req.old_password}",
        f"--newpassword={req.new_password}",
        "--ipaddress=127.0.0.1",
        "--use-kerberos=off"
    ]
    code, stdout, stderr = run_cmd(cmd, timeout=15)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if code == 0:
        cursor.execute("""
            INSERT INTO self_service_password_logs (
                username, method, recipient, otp_code, otp_expires_at, status,
                ip_address, user_agent, created_at, completed_at, notes
            ) VALUES (?, 'OLD_PASSWORD', 'Direct Authentication', NULL, NULL, 'COMPLETED', ?, ?, ?, ?, 'Password changed successfully')
        """, (clean_user, client_ip, request.headers.get("User-Agent", ""), time.time(), time.time()))
        conn.commit()
        conn.close()

        log_audit("SSPR_PASSWORD_CHANGED", clean_user, "active_directory", "SUCCESS", {"method": "OLD_PASSWORD", "ip": client_ip})
        return {
            "status": "success",
            "message": "Password changed successfully! You can now log in with your new password."
        }
    else:
        err_msg = stderr.strip() or stdout.strip()
        if "Authentication failed" in err_msg or "wrong" in err_msg.lower() or "NT_STATUS_WRONG_PASSWORD" in err_msg:
            user_facing_err = "Authentication failed: Current password is incorrect."
        elif "check_password_restrictions" in err_msg or "NT_STATUS_PASSWORD_RESTRICTION" in err_msg:
            user_facing_err = "The new password does not meet domain password policy (minimum password age, history, or complexity restrictions)."
        else:
            user_facing_err = f"Password change rejected: {err_msg}"

        cursor.execute("""
            INSERT INTO self_service_password_logs (
                username, method, recipient, otp_code, otp_expires_at, status,
                ip_address, user_agent, created_at, completed_at, notes
            ) VALUES (?, 'OLD_PASSWORD', 'Direct Authentication', NULL, NULL, 'FAILED', ?, ?, ?, ?, ?)
        """, (clean_user, client_ip, request.headers.get("User-Agent", ""), time.time(), time.time(), user_facing_err))
        conn.commit()
        conn.close()

        log_audit("SSPR_PASSWORD_FAILED", clean_user, "active_directory", "FAILED", {"method": "OLD_PASSWORD", "ip": client_ip, "error": user_facing_err})
        raise HTTPException(status_code=400, detail=user_facing_err)


@router.post("/password/request-otp")
def request_password_reset_otp(req: PasswordResetOtpRequest, request: Request):
    """Validates user in Active Directory and dispatches an OTP via Email or Mobile SMS."""
    settings = get_sspr_settings()
    if not settings.get("enabled", 1):
        raise HTTPException(status_code=403, detail="Self Service Password Reset is currently disabled by administrator.")

    client_ip = request.client.host if request.client else "127.0.0.1"
    clean_user = req.username.strip()

    # Look up user in AD
    user_info = lookup_ad_user(clean_user)
    if not user_info.get("found"):
        raise HTTPException(status_code=404, detail=f"Domain account '{clean_user}' not found. Please verify your username.")

    if user_info.get("is_disabled"):
        raise HTTPException(status_code=403, detail="This account has been disabled. Please contact your domain administrator.")

    real_username = user_info["username"]
    channel = req.channel.lower()

    if channel == "email":
        if not settings.get("allow_email_reset", 1):
            raise HTTPException(status_code=403, detail="Password reset via Email is not enabled.")
        user_email = user_info.get("email")
        if not user_email or "@" not in user_email:
            raise HTTPException(
                status_code=400,
                detail=f"No email address is registered on account '{real_username}'. Please contact your Domain Administrator to update your profile."
            )

        # Generate OTP
        otp = f"{secrets.randbelow(900000) + 100000}"
        expiry_min = int(settings.get("otp_expiry_minutes", 10))
        expires_at = time.time() + (expiry_min * 60)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO self_service_password_logs (
                username, method, recipient, otp_code, otp_expires_at, status,
                ip_address, user_agent, created_at, completed_at, notes
            ) VALUES (?, 'EMAIL_OTP', ?, ?, ?, 'PENDING_OTP', ?, ?, ?, NULL, 'Verification code dispatched to registered email')
        """, (real_username, user_email, otp, expires_at, client_ip, request.headers.get("User-Agent", ""), time.time()))
        reset_id = cursor.lastrowid
        conn.commit()
        conn.close()

        email_body = f"Hello {real_username},\n\nA password reset request was initiated for your ZclockID account from IP {client_ip}.\n\nYour verification code is: {otp}\n\nThis code will expire in {expiry_min} minutes. If you did not request this, please contact your security administrator immediately."
        dispatch_email(user_email, "ZclockID Password Reset Verification Code", email_body, settings)
        masked = mask_email(user_email)

        log_audit("SSPR_OTP_SENT", real_username, "email", "SUCCESS", {"recipient": masked, "ip": client_ip})

        return {
            "status": "otp_sent",
            "reset_id": reset_id,
            "username": real_username,
            "channel": "email",
            "recipient_masked": masked,
            "otp_debug": otp if not settings.get("email_smtp_enabled") else None,
            "message": f"Verification code has been sent to your registered email ({masked})."
        }

    elif channel == "sms":
        if not settings.get("allow_otp_reset", 1):
            raise HTTPException(status_code=403, detail="Password reset via Mobile SMS is not enabled.")
        user_mobile = user_info.get("mobile")
        if not user_mobile or len(re.sub(r'[^\d]', '', user_mobile)) < 7:
            raise HTTPException(
                status_code=400,
                detail=f"No mobile phone number is registered on account '{real_username}'. Please contact your Domain Administrator to update your profile."
            )

        # Generate OTP
        otp = f"{secrets.randbelow(900000) + 100000}"
        expiry_min = int(settings.get("otp_expiry_minutes", 10))
        expires_at = time.time() + (expiry_min * 60)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO self_service_password_logs (
                username, method, recipient, otp_code, otp_expires_at, status,
                ip_address, user_agent, created_at, completed_at, notes
            ) VALUES (?, 'SMS_OTP', ?, ?, ?, 'PENDING_OTP', ?, ?, ?, NULL, 'Verification code dispatched to registered mobile')
        """, (real_username, user_mobile, otp, expires_at, client_ip, request.headers.get("User-Agent", ""), time.time()))
        reset_id = cursor.lastrowid
        conn.commit()
        conn.close()

        sms_msg = settings.get("sms_template", "Your ZclockID password reset verification code is {otp}. Valid for 10 minutes.").replace("{otp}", otp).replace("{username}", real_username)
        dispatch_sms(user_mobile, sms_msg, settings)
        masked = mask_phone(user_mobile)

        log_audit("SSPR_OTP_SENT", real_username, "sms", "SUCCESS", {"recipient": masked, "ip": client_ip})

        return {
            "status": "otp_sent",
            "reset_id": reset_id,
            "username": real_username,
            "channel": "sms",
            "recipient_masked": masked,
            "otp_debug": otp if settings.get("sms_gateway_type") == "simulated" else None,
            "message": f"Verification code has been sent to your registered mobile ({masked})."
        }

    else:
        raise HTTPException(status_code=400, detail="Invalid verification channel requested.")


@router.post("/password/verify-and-reset")
def verify_otp_and_reset_password(req: PasswordResetVerifyRequest, request: Request):
    """Verifies the dispatched OTP code and resets the user's password in Active Directory."""
    settings = get_sspr_settings()
    if not settings.get("enabled", 1):
        raise HTTPException(status_code=403, detail="Self Service Password Reset is currently disabled by administrator.")

    client_ip = request.client.host if request.client else "127.0.0.1"
    clean_user = req.username.strip()
    clean_otp = req.otp_code.strip()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM self_service_password_logs 
        WHERE id = ? AND username = ?
    """, (req.reset_id, clean_user))
    log_entry = cursor.fetchone()

    if not log_entry:
        conn.close()
        raise HTTPException(status_code=404, detail="Invalid password reset request identifier.")

    if log_entry["status"] != "PENDING_OTP":
        conn.close()
        raise HTTPException(status_code=400, detail="This reset request has already been used or has expired.")

    if time.time() > log_entry["otp_expires_at"]:
        cursor.execute("UPDATE self_service_password_logs SET status = 'EXPIRED' WHERE id = ?", (req.reset_id,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="Verification code has expired. Please request a new code.")

    if log_entry["otp_code"] != clean_otp:
        cursor.execute("UPDATE self_service_password_logs SET notes = notes || ' | Incorrect OTP entered' WHERE id = ?", (req.reset_id,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid verification code entered. Please try again.")

    # Validate password rules
    min_len = int(settings.get("min_password_length", 8))
    if len(req.new_password) < min_len:
        conn.close()
        raise HTTPException(status_code=400, detail=f"New password must be at least {min_len} characters long.")

    if settings.get("require_complexity", 1):
        is_valid, msg = validate_ad_password_complexity(req.new_password)
        if not is_valid:
            conn.close()
            raise HTTPException(status_code=400, detail=msg)

    # Use administrative credentials to set the password
    admin_user, admin_pass = get_ad_creds()
    cmd = [
        "samba-tool", "user", "setpassword",
        clean_user,
        f"--newpassword={req.new_password}",
        f"-U{admin_user}",
        f"--password={admin_pass}"
    ]
    code, stdout, stderr = run_cmd(cmd, timeout=15)

    if code != 0:
        err_msg = stderr.strip() or stdout.strip()
        cursor.execute("""
            UPDATE self_service_password_logs 
            SET status = 'FAILED', notes = ? 
            WHERE id = ?
        """, (f"Active Directory reset failed: {err_msg}", req.reset_id))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail=f"Failed to set new password in Active Directory: {err_msg}")

    # Mark as completed
    cursor.execute("""
        UPDATE self_service_password_logs 
        SET status = 'COMPLETED', completed_at = ?, notes = 'Password reset completed via OTP'
        WHERE id = ?
    """, (time.time(), req.reset_id))
    conn.commit()
    conn.close()

    log_audit("SSPR_PASSWORD_RESET_SUCCESS", clean_user, "active_directory", "SUCCESS", {"method": log_entry["method"], "ip": client_ip})

    return {
        "status": "success",
        "message": "Your password has been reset successfully! You can now log in with your new password."
    }


# ==================== ADMINISTRATOR MANAGEMENT & LOGS ====================

@router.get("/password/settings")
def get_password_reset_settings():
    """Returns administrator settings for Self Service Password Reset."""
    settings = get_sspr_settings()
    return {"status": "success", "settings": settings}


@router.post("/password/settings")
def update_password_reset_settings(req: PasswordResetSettingsUpdate):
    """Updates administrator settings for Self Service Password Reset."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE self_service_password_settings
        SET enabled = ?,
            allow_old_password_reset = ?,
            allow_email_reset = ?,
            allow_otp_reset = ?,
            min_password_length = ?,
            require_complexity = ?,
            otp_expiry_minutes = ?,
            max_daily_attempts = ?,
            email_smtp_enabled = ?,
            smtp_host = ?,
            smtp_port = ?,
            smtp_user = ?,
            smtp_pass = ?,
            smtp_from = ?,
            sms_gateway_type = ?,
            sms_gateway_url = ?,
            sms_api_key = ?,
            sms_sender_id = ?,
            sms_template = ?,
            updated_at = ?
        WHERE id = 1
    """, (
        1 if req.enabled else 0,
        1 if req.allow_old_password_reset else 0,
        1 if req.allow_email_reset else 0,
        1 if req.allow_otp_reset else 0,
        req.min_password_length,
        1 if req.require_complexity else 0,
        req.otp_expiry_minutes,
        req.max_daily_attempts,
        1 if req.email_smtp_enabled else 0,
        req.smtp_host.strip(),
        req.smtp_port,
        req.smtp_user.strip(),
        req.smtp_pass.strip(),
        req.smtp_from.strip(),
        req.sms_gateway_type.strip(),
        req.sms_gateway_url.strip(),
        req.sms_api_key.strip(),
        req.sms_sender_id.strip(),
        req.sms_template.strip(),
        time.time()
    ))
    conn.commit()
    conn.close()

    log_audit("SSPR_SETTINGS_UPDATED", "admin", "appliance", "SUCCESS", {})
    return {"status": "success", "message": "Self Service Password Reset settings updated successfully."}


@router.get("/password/logs")
def get_password_reset_logs(
    month: Optional[str] = None,
    status_filter: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 500
):
    """Returns password reset logs with filtering by month, status, and search query."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = "SELECT * FROM self_service_password_logs WHERE 1=1"
    params = []

    if status_filter and status_filter.lower() != "all":
        query += " AND status = ?"
        params.append(status_filter.upper())

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        query += " AND (LOWER(username) LIKE ? OR LOWER(recipient) LIKE ? OR LOWER(ip_address) LIKE ? OR LOWER(method) LIKE ?)"
        params.extend([term, term, term, term])

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    cursor.execute(query, params)
    rows = cursor.fetchall()

    logs = []
    available_months = set()
    total_completed = 0
    total_failed = 0

    for r in rows:
        d = dict(r)
        ts = d.get("created_at") or time.time()
        m_str = datetime.fromtimestamp(ts).strftime("%Y-%m")
        available_months.add(m_str)

        if d.get("status") == "COMPLETED":
            total_completed += 1
        elif d.get("status") in ["FAILED", "EXPIRED"]:
            total_failed += 1

        # Apply in-memory month filter if specified
        if month and month.lower() != "all" and m_str != month:
            continue

        logs.append(d)

    conn.close()

    sorted_months = sorted(list(available_months), reverse=True)

    return {
        "count": len(logs),
        "total_completed": total_completed,
        "total_failed": total_failed,
        "available_months": sorted_months,
        "logs": logs
    }


@router.get("/password/logs/export")
def export_password_reset_logs_csv(
    method: Optional[str] = None,
    status: Optional[str] = None,
    month: Optional[str] = None,
    search: Optional[str] = None
):
    """Generates a downloadable CSV export of all Self Service Password Reset logs."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM self_service_password_logs ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Username", "Method", "Recipient", "Status", "IP Address", "Created At", "Completed At", "Notes"])

    for r in rows:
        d = dict(r)
        ts = d.get("created_at") or 0
        m_str = datetime.fromtimestamp(ts).strftime("%Y-%m") if ts else ""
        if month and month.lower() != "all" and m_str != month:
            continue

        if method and method.lower() != "all" and d.get("method") != method:
            continue

        if status and status.lower() != "all" and d.get("status") != status:
            continue

        if search and search.strip():
            term = search.strip().lower()
            haystack = f"{d.get('username') or ''} {d.get('recipient') or ''} {d.get('ip_address') or ''} {d.get('notes') or ''}".lower()
            if term not in haystack:
                continue

        created_fmt = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-"
        comp_ts = d.get("completed_at")
        completed_fmt = datetime.fromtimestamp(comp_ts).strftime("%Y-%m-%d %H:%M:%S") if comp_ts else "-"

        writer.writerow([
            d["id"],
            d["username"],
            d["method"],
            d.get("recipient", "-"),
            d["status"],
            d.get("ip_address", "-"),
            created_fmt,
            completed_fmt,
            d.get("notes", "")
        ])

    csv_data = output.getvalue()
    filename = f"zclockid-password-resets-{month or 'all'}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/registrations/export")
def export_registration_logs_csv(
    status_filter: Optional[str] = None,
    month: Optional[str] = None,
    search: Optional[str] = None
):
    """Generates a downloadable CSV export of all Self-Registration requests."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM self_registrations ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Username", "Full Name", "Email", "Mobile", "Department", "Status", "IP Address", "Created At", "Approved At", "Approved By", "Notes"])

    for r in rows:
        d = dict(r)
        ts = d.get("created_at") or 0
        m_str = datetime.fromtimestamp(ts).strftime("%Y-%m") if ts else ""
        if month and month.lower() != "all" and m_str != month:
            continue

        if status_filter and status_filter.lower() != "all" and d.get("status") != status_filter:
            continue

        if search and search.strip():
            term = search.strip().lower()
            haystack = f"{d.get('username') or ''} {d.get('given_name') or ''} {d.get('surname') or ''} {d.get('email') or ''} {d.get('mobile') or ''} {d.get('department') or ''}".lower()
            if term not in haystack:
                continue

        created_fmt = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-"
        app_ts = d.get("approved_at")
        approved_fmt = datetime.fromtimestamp(app_ts).strftime("%Y-%m-%d %H:%M:%S") if app_ts else "-"

        full_name = f"{d.get('given_name') or ''} {d.get('surname') or ''}".strip()

        writer.writerow([
            d["id"],
            d["username"],
            full_name,
            d.get("email", "-"),
            d.get("mobile", "-"),
            d.get("department", "-"),
            d["status"],
            d.get("ip_address", "-"),
            created_fmt,
            approved_fmt,
            d.get("approved_by", "-"),
            d.get("notes", "")
        ])

    csv_data = output.getvalue()
    filename = f"zclockid-registrations-{month or 'all'}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
