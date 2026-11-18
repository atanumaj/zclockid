"""
ZclockID Password Expiry and Fine-Grained Password Settings Object (PSO) Service
Manages domain password expiry policies, ZclockID-SelfRegistered group,
ZclockID-SelfReg-PSO fine-grained password settings, resultant PSO queries,
expiry reminders at 14, 7, and 1 days, and bulk expiry policy application.
"""

import os
import time
import fcntl
import sqlite3
import logging
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from api.core.config import DB_PATH, DATA_DIR, SAMBA_LDB_PATH, DEFAULT_REALM
from api.services.system_service import run_cmd, log_audit, get_primary_realm
from api.core.security import get_ad_creds
from api.services.samdb_service import samdb_newgroup, samdb_add_group_member, run_samba_tool_authenticated

logger = logging.getLogger("zclockid.password_expiry")
REMINDER_LOCK_FILE = DATA_DIR / "password_expiry_reminders.lock"

# Excluded system / service accounts from bulk expiry policy
EXCLUDED_USERNAMES = {"administrator", "guest", "krbtgt", "dns-zclockid"}


def is_service_account(username: str) -> bool:
    u = username.lower().strip()
    if u in EXCLUDED_USERNAMES:
        return True
    if u.endswith("$"):
        return True
    if u.startswith("svc_") or u.startswith("svc-") or u.startswith("dns-"):
        return True
    return False


def get_db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def ensure_selfreg_group_and_pso(max_pwd_age_days: Optional[int] = None) -> Dict[str, Any]:
    """
    Ensures group ZclockID-SelfRegistered and PSO ZclockID-SelfReg-PSO exist in Active Directory.
    Backfills group membership for all self-registered users.
    If the domain functional level doesn't support PSOs, logs a warning but never fails.
    """
    admin_user, admin_pass = get_ad_creds()
    realm = get_primary_realm()

    # 1. Resolve max_pwd_age_days (configurable 30-730, default 365)
    if max_pwd_age_days is None:
        try:
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT pso_max_pwd_age_days FROM self_registration_settings WHERE id = 1")
            row = cursor.fetchone()
            conn.close()
            if row and row[0]:
                max_pwd_age_days = int(row[0])
        except Exception:
            pass
    if max_pwd_age_days is None:
        max_pwd_age_days = 365
    max_pwd_age_days = max(30, min(730, max_pwd_age_days))

    # 2. Ensure group ZclockID-SelfRegistered exists
    group_created = False
    try:
        code, stdout, _ = run_cmd([
            "ldbsearch", "-H", str(SAMBA_LDB_PATH),
            "(&(objectClass=group)(sAMAccountName=ZclockID-SelfRegistered))", "dn"
        ], timeout=8)
        if code != 0 or "dn: " not in stdout:
            try:
                samdb_newgroup("ZclockID-SelfRegistered", description="ZclockID Self-Registered Users")
                group_created = True
                logger.info("Created Active Directory group 'ZclockID-SelfRegistered'.")
            except Exception as e_grp:
                logger.warning("Could not create group ZclockID-SelfRegistered: %s", e_grp)
    except Exception as e:
        logger.warning("Error checking/creating ZclockID-SelfRegistered group: %s", e)

    # 3. Backfill users with employeeType: Self-Registered into ZclockID-SelfRegistered
    backfilled_count = 0
    try:
        c_users, o_users, _ = run_cmd([
            "ldbsearch", "-H", str(SAMBA_LDB_PATH),
            "(&(objectClass=user)(!(objectClass=computer))(|(employeeType=Self-Registered)(comment=*ZCLOCKID_SELF_REGISTERED*)(description=*Self-Registered*)))",
            "sAMAccountName", "memberOf"
        ], timeout=10)
        if c_users == 0:
            current_user = None
            memberships = []
            for line in o_users.splitlines():
                line = line.strip()
                if not line:
                    if current_user:
                        if not any("ZclockID-SelfRegistered" in m for m in memberships):
                            try:
                                samdb_add_group_member("ZclockID-SelfRegistered", current_user)
                                backfilled_count += 1
                            except Exception as e_add:
                                logger.warning("Failed to add %s to ZclockID-SelfRegistered: %s", current_user, e_add)
                    current_user = None
                    memberships = []
                    continue
                if line.startswith("sAMAccountName:"):
                    current_user = line.split(":", 1)[1].strip()
                elif line.startswith("memberOf:"):
                    memberships.append(line.split(":", 1)[1].strip())
            if current_user and not any("ZclockID-SelfRegistered" in m for m in memberships):
                try:
                    samdb_add_group_member("ZclockID-SelfRegistered", current_user)
                    backfilled_count += 1
                except Exception as e_add:
                    logger.warning("Failed to add %s to ZclockID-SelfRegistered: %s", current_user, e_add)
    except Exception as e:
        logger.warning("Error backfilling users into ZclockID-SelfRegistered: %s", e)

    # 4. Create or update Password Settings Object (PSO): ZclockID-SelfReg-PSO
    pso_status = "ok"
    try:
        # Check if PSO exists
        c_show, o_show, e_show = run_samba_tool_authenticated([
            "domain", "passwordsettings", "pso", "show", "ZclockID-SelfReg-PSO"
        ], timeout=10)

        if c_show == 0:
            # Update max-pwd-age
            run_samba_tool_authenticated([
                "domain", "passwordsettings", "pso", "set", "ZclockID-SelfReg-PSO",
                f"--max-pwd-age={max_pwd_age_days}"
            ], timeout=15)
        else:
            # Create PSO: precedence 10, max-pwd-age
            c_create, o_create, e_create = run_samba_tool_authenticated([
                "domain", "passwordsettings", "pso", "create", "ZclockID-SelfReg-PSO",
                "10",
                f"--max-pwd-age={max_pwd_age_days}"
            ], timeout=15)
            err_msg = (e_create or o_create or "").lower()
            if c_create != 0:
                if "functional level" in err_msg or "not supported" in err_msg or "schema" in err_msg:
                    logger.warning("Active Directory Domain Functional Level does not support Password Settings Objects (PSOs). Warning: %s", err_msg)
                    return {
                        "status": "warning",
                        "warning": "Domain functional level does not support PSOs",
                        "max_pwd_age_days": max_pwd_age_days,
                        "backfilled": backfilled_count
                    }
                else:
                    logger.warning("Failed to create PSO ZclockID-SelfReg-PSO: %s", e_create or o_create)

        # Apply PSO to group ZclockID-SelfRegistered
        c_app, o_app, e_app = run_samba_tool_authenticated([
            "domain", "passwordsettings", "pso", "apply", "ZclockID-SelfReg-PSO",
            "ZclockID-SelfRegistered"
        ], timeout=15)
        if c_app != 0:
            err_app = (e_app or o_app or "").lower()
            if "functional level" in err_app or "not supported" in err_app:
                logger.warning("Active Directory Domain Functional Level does not support PSOs: %s", err_app)
                return {
                    "status": "warning",
                    "warning": "Domain functional level does not support PSOs",
                    "max_pwd_age_days": max_pwd_age_days,
                    "backfilled": backfilled_count
                }
    except Exception as e:
        logger.warning("Domain functional level does not support Password Settings Objects (PSOs): %s", e)
        return {
            "status": "warning",
            "warning": str(e),
            "max_pwd_age_days": max_pwd_age_days,
            "backfilled": backfilled_count
        }

    return {
        "status": "success",
        "group_created": group_created,
        "backfilled": backfilled_count,
        "pso": "ZclockID-SelfReg-PSO",
        "max_pwd_age_days": max_pwd_age_days
    }


def add_user_to_selfreg_group(username: str) -> bool:
    """Adds a self-registered user to ZclockID-SelfRegistered group and ensures PSO applies."""
    try:
        ensure_selfreg_group_and_pso()
        samdb_add_group_member("ZclockID-SelfRegistered", username)
        return True
    except Exception as e:
        logger.warning("Failed to add user %s to ZclockID-SelfRegistered: %s", username, e)
        return False


def get_user_password_info(username: str) -> Dict[str, Any]:
    """
    Queries Active Directory for user's password settings, resultant PSO, and expiry date.
    Returns:
      resultant_pso: Name of the PSO applying or None
      expires_on: Formatted expiry string, 'Never', or 'Expired (Must change)'
      never_expires: bool
      is_expired: bool
      days_remaining: float or None
      pwd_last_set: int (FileTime)
    """
    clean_user = username.strip()
    code, stdout, _ = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        f"(sAMAccountName={clean_user})",
        "userAccountControl", "pwdLastSet", "msDS-ResultantPSO", "accountExpires", "employeeType"
    ], timeout=6)

    uac = 512
    pwd_last_set = 0
    resultant_pso = None
    account_expires = 0

    if code == 0:
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("userAccountControl:"):
                try:
                    uac = int(line.split(":", 1)[1].strip())
                except Exception:
                    pass
            elif line.startswith("pwdLastSet:"):
                try:
                    pwd_last_set = int(line.split(":", 1)[1].strip())
                except Exception:
                    pass
            elif line.startswith("accountExpires:"):
                try:
                    account_expires = int(line.split(":", 1)[1].strip())
                except Exception:
                    pass
            elif line.startswith("msDS-ResultantPSO:"):
                val = line.split(":", 1)[1].strip()
                # parse CN=... from DN
                for part in val.split(","):
                    if part.strip().startswith("CN="):
                        resultant_pso = part.strip()[3:]
                        break

    # If resultant_pso was not returned by ldbsearch, try samba-tool domain passwordsettings pso show-user
    if not resultant_pso:
        try:
            c_p, o_p, _ = run_samba_tool_authenticated([
                "domain", "passwordsettings", "pso", "show-user", clean_user
            ], timeout=5)
            if c_p == 0 and "Password information for PSO '" in o_p:
                start_idx = o_p.find("Password information for PSO '") + len("Password information for PSO '")
                end_idx = o_p.find("'", start_idx)
                if end_idx != -1:
                    resultant_pso = o_p[start_idx:end_idx].strip()
        except Exception:
            pass

    # Expiry calculation
    never_expires = bool(uac & 65536)
    if never_expires:
        return {
            "username": clean_user,
            "resultant_pso": resultant_pso,
            "expires_on": "Never",
            "never_expires": True,
            "is_expired": False,
            "days_remaining": None,
            "pwd_last_set": pwd_last_set
        }

    if pwd_last_set == 0:
        return {
            "username": clean_user,
            "resultant_pso": resultant_pso,
            "expires_on": "Expired (Must change)",
            "never_expires": False,
            "is_expired": True,
            "days_remaining": 0.0,
            "pwd_last_set": 0
        }

    # Determine max password age in days
    max_pwd_age_days = 42 # AD default
    if resultant_pso:
        # Check if it is ZclockID-SelfReg-PSO
        if resultant_pso == "ZclockID-SelfReg-PSO":
            try:
                conn = get_db_conn()
                cursor = conn.cursor()
                cursor.execute("SELECT pso_max_pwd_age_days FROM self_registration_settings WHERE id = 1")
                row = cursor.fetchone()
                conn.close()
                if row and row[0]:
                    max_pwd_age_days = int(row[0])
            except Exception:
                max_pwd_age_days = 365
        else:
            # Query PSO details from AD
            try:
                c_pso, o_pso, _ = run_cmd([
                    "samba-tool", "domain", "passwordsettings", "pso", "show", resultant_pso
                ], timeout=5)
                for l in o_pso.splitlines():
                    if "Maximum password age (days):" in l:
                        max_pwd_age_days = int(l.split(":", 1)[1].strip())
            except Exception:
                pass
    else:
        # Domain default password policy
        try:
            c_dom, o_dom, _ = run_cmd(["samba-tool", "domain", "passwordsettings", "show"], timeout=5)
            for l in o_dom.splitlines():
                if "Maximum password age (days):" in l:
                    max_pwd_age_days = int(l.split(":", 1)[1].strip())
        except Exception:
            pass

    if max_pwd_age_days <= 0:
        return {
            "username": clean_user,
            "resultant_pso": resultant_pso,
            "expires_on": "Never",
            "never_expires": True,
            "is_expired": False,
            "days_remaining": None,
            "pwd_last_set": pwd_last_set
        }

    # Convert Windows FileTime (100-ns intervals since Jan 1, 1601 UTC) to Unix timestamp
    pwd_epoch = (pwd_last_set - 116444736000000000) / 10000000.0
    expires_epoch = pwd_epoch + (max_pwd_age_days * 86400.0)
    now = time.time()
    days_remaining = (expires_epoch - now) / 86400.0
    dt_expires = datetime.fromtimestamp(expires_epoch, timezone.utc)
    expires_str = dt_expires.strftime("%Y-%m-%d %H:%M:%S UTC")

    is_expired = days_remaining <= 0
    if is_expired:
        expires_on_display = f"Expired ({expires_str})"
    else:
        expires_on_display = expires_str

    return {
        "username": clean_user,
        "resultant_pso": resultant_pso,
        "expires_on": expires_on_display,
        "expires_timestamp": expires_epoch,
        "never_expires": False,
        "is_expired": is_expired,
        "days_remaining": days_remaining,
        "pwd_last_set": pwd_last_set
    }


def get_effective_max_pwd_age(username: Optional[str] = None, resultant_pso: Optional[str] = None) -> int:
    """Returns effective max password age in days for the user/PSO, or default domain policy."""
    pso = resultant_pso
    if not pso and username:
        try:
            c_p, o_p, _ = run_samba_tool_authenticated([
                "domain", "passwordsettings", "pso", "show-user", username
            ], timeout=5)
            if c_p == 0 and "Password information for PSO '" in o_p:
                start_idx = o_p.find("Password information for PSO '") + len("Password information for PSO '")
                end_idx = o_p.find("'", start_idx)
                if end_idx != -1:
                    pso = o_p[start_idx:end_idx].strip()
        except Exception:
            pass

    if pso:
        if pso == "ZclockID-SelfReg-PSO":
            try:
                conn = get_db_conn()
                cursor = conn.cursor()
                cursor.execute("SELECT pso_max_pwd_age_days FROM self_registration_settings WHERE id = 1")
                row = cursor.fetchone()
                conn.close()
                if row and row[0]:
                    return int(row[0])
            except Exception:
                pass
            return 365
        else:
            try:
                c_pso, o_pso, _ = run_cmd([
                    "samba-tool", "domain", "passwordsettings", "pso", "show", pso
                ], timeout=5)
                if c_pso == 0:
                    for l in o_pso.splitlines():
                        if "Maximum password age (days):" in l:
                            return int(l.split(":", 1)[1].strip())
            except Exception:
                pass

    # Fallback to domain default password policy
    try:
        c_dom, o_dom, _ = run_cmd(["samba-tool", "domain", "passwordsettings", "show"], timeout=5)
        if c_dom == 0:
            for l in o_dom.splitlines():
                if "Maximum password age (days):" in l:
                    return int(l.split(":", 1)[1].strip())
    except Exception:
        pass

    return 42  # Default Active Directory max password age


def compute_effective_expiry(pwd_last_set: int, username: Optional[str] = None, resultant_pso: Optional[str] = None, now: Optional[float] = None) -> Tuple[bool, int, Optional[float]]:
    """
    Computes whether a password would be expired under effective policy (ignoring DONT_EXPIRE_PASSWORD flag).
    Returns (will_expire_immediately, max_pwd_age_days, expires_epoch).
    """
    if now is None:
        now = time.time()

    if pwd_last_set == 0:
        return True, 0, 0.0

    max_pwd_age_days = get_effective_max_pwd_age(username, resultant_pso)
    if max_pwd_age_days <= 0:
        return False, max_pwd_age_days, None

    pwd_epoch = (pwd_last_set - 116444736000000000) / 10000000.0
    expires_epoch = pwd_epoch + (max_pwd_age_days * 86400.0)
    will_expire = expires_epoch <= now
    return will_expire, max_pwd_age_days, expires_epoch


def get_password_expiry_report() -> Dict[str, Any]:
    """
    Generates report of user password expiry states across Active Directory.
    Identifies accounts with 'never expires' set, eligible accounts to update,
    and excluded service/admin accounts.
    Also computes whether (pwdLastSet + effective max-pwd-age) is already in the past
    for each eligible user to report accounts that will immediately expire.
    """
    code, stdout, stderr = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        "(&(objectClass=user)(!(objectClass=computer)))",
        "sAMAccountName", "userAccountControl", "pwdLastSet", "userPrincipalName", "isCriticalSystemObject", "msDS-ResultantPSO"
    ], timeout=15)

    if code != 0:
        return {
            "total_users": 0,
            "eligible_count": 0,
            "compliant_count": 0,
            "excluded_count": 0,
            "immediate_expired_count": 0,
            "immediate_expired_users": [],
            "eligible_users": [],
            "excluded_users": []
        }

    users_list = []
    current_u = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            if current_u.get("username"):
                users_list.append(current_u)
            current_u = {}
            continue
        if line.startswith("sAMAccountName:"):
            current_u["username"] = line.split(":", 1)[1].strip()
        elif line.startswith("userAccountControl:"):
            try:
                current_u["uac"] = int(line.split(":", 1)[1].strip())
            except Exception:
                current_u["uac"] = 512
        elif line.startswith("userPrincipalName:"):
            current_u["upn"] = line.split(":", 1)[1].strip()
        elif line.startswith("pwdLastSet:"):
            try:
                current_u["pwd_last_set"] = int(line.split(":", 1)[1].strip())
            except Exception:
                current_u["pwd_last_set"] = 0
        elif line.startswith("isCriticalSystemObject:"):
            current_u["is_critical"] = line.split(":", 1)[1].strip().upper() == "TRUE"
        elif line.startswith("msDS-ResultantPSO:"):
            val = line.split(":", 1)[1].strip()
            for part in val.split(","):
                if part.strip().startswith("CN="):
                    current_u["resultant_pso"] = part.strip()[3:]
                    break
    if current_u.get("username"):
        users_list.append(current_u)

    eligible_users = []
    excluded_users = []
    immediate_expired_users = []
    compliant_count = 0

    now = time.time()
    for u in users_list:
        name = u["username"]
        uac = u.get("uac", 512)
        has_never_expires = bool(uac & 65536)

        if is_service_account(name) or u.get("is_critical"):
            excluded_users.append(name)
        elif has_never_expires:
            pwd_ls = u.get("pwd_last_set", 0)
            pso_name = u.get("resultant_pso")
            will_expire, max_age, exp_epoch = compute_effective_expiry(pwd_ls, username=name, resultant_pso=pso_name, now=now)

            user_entry = {
                "username": name,
                "user_principal_name": u.get("upn", ""),
                "never_expires": True,
                "user_account_control": uac,
                "pwd_last_set": pwd_ls,
                "resultant_pso": pso_name,
                "effective_max_pwd_age_days": max_age,
                "will_expire_immediately": will_expire
            }
            eligible_users.append(user_entry)
            if will_expire:
                immediate_expired_users.append(name)
        else:
            compliant_count += 1

    return {
        "total_users": len(users_list),
        "eligible_count": len(eligible_users),
        "compliant_count": compliant_count,
        "excluded_count": len(excluded_users),
        "immediate_expired_count": len(immediate_expired_users),
        "immediate_expired_users": immediate_expired_users,
        "eligible_users": eligible_users,
        "excluded_users": excluded_users
    }


def apply_bulk_expiry_policy(admin_user: str) -> Dict[str, Any]:
    """
    Bulk action to remove DONT_EXPIRE_PASSWORD flag from eligible users,
    enforcing domain password expiry. Excludes Administrator and service accounts.
    Requires fulladmin role, writes audit log.
    """
    report = get_password_expiry_report()
    eligible = report.get("eligible_users", [])
    immediate_expired_count = report.get("immediate_expired_count", 0)
    immediate_expired_users = report.get("immediate_expired_users", [])

    modified_users = []
    for u in eligible:
        username = u["username"]
        uac = u["user_account_control"]
        new_uac = uac & ~65536  # Clear DONT_EXPIRE_PASSWORD (65536)

        # Look up user DN
        c_dn, o_dn, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(sAMAccountName={username})", "dn"], timeout=5)
        if c_dn == 0 and "dn: " in o_dn:
            u_dn = [l[4:].strip() for l in o_dn.splitlines() if l.startswith("dn: ")][0]
            ldif = f"dn: {u_dn}\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: {new_uac}\n-\n"
            proc = subprocess.run(["ldbmodify", "-H", str(SAMBA_LDB_PATH)], input=ldif, text=True, capture_output=True)
            if proc.returncode == 0:
                modified_users.append(username)
            else:
                logger.warning("Failed to clear DONT_EXPIRE_PASSWORD for %s: %s", username, proc.stderr)

    log_audit("APPLY_EXPIRY_POLICY", admin_user, "active_directory", "SUCCESS", {
        "modified_count": len(modified_users),
        "modified_users": modified_users,
        "immediate_expired_count": immediate_expired_count,
        "immediate_expired_users": immediate_expired_users
    })

    return {
        "status": "success",
        "message": f"Successfully applied password expiry policy to {len(modified_users)} user(s).",
        "modified_count": len(modified_users),
        "modified_users": modified_users,
        "immediate_expired_count": immediate_expired_count,
        "immediate_expired_users": immediate_expired_users
    }


def run_password_expiry_reminders(current_time: Optional[float] = None) -> Dict[str, Any]:
    """
    Daily job: sends SMS or email reminders to self-registered users at
    14, 7, and 1 days before password expiry.
    Ensures at most one notification per threshold per password cycle.
    Writes audit log for each dispatch.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(REMINDER_LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        os.close(lock_fd)
        logger.debug("Password expiry reminder job is already running on another worker. Skipping.")
        return {"status": "skipped", "reason": "locked"}

    try:
        now = current_time if current_time is not None else time.time()
        conn = get_db_conn()
        cursor = conn.cursor()

        # Load registration settings for SMS/email gateways
        cursor.execute("SELECT * FROM self_registration_settings WHERE id = 1")
        reg_row = cursor.fetchone()
        reg_settings = dict(reg_row) if reg_row else {}

        # Query self-registered users
        code, stdout, _ = run_cmd([
            "ldbsearch", "-H", str(SAMBA_LDB_PATH),
            "(&(objectClass=user)(!(objectClass=computer))(|(employeeType=Self-Registered)(memberOf=*CN=ZclockID-SelfRegistered*)))",
            "sAMAccountName", "mail", "telephoneNumber", "userAccountControl", "pwdLastSet"
        ], timeout=15)

        if code != 0:
            conn.close()
            return {"status": "error", "message": "Failed to query Active Directory"}

        users_to_check = []
        cur_u = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if cur_u.get("username"):
                    users_to_check.append(cur_u)
                cur_u = {}
                continue
            if line.startswith("sAMAccountName:"):
                cur_u["username"] = line.split(":", 1)[1].strip()
            elif line.startswith("mail:"):
                cur_u["email"] = line.split(":", 1)[1].strip()
            elif line.startswith("telephoneNumber:"):
                cur_u["mobile"] = line.split(":", 1)[1].strip()
            elif line.startswith("userAccountControl:"):
                try:
                    cur_u["uac"] = int(line.split(":", 1)[1].strip())
                except Exception:
                    cur_u["uac"] = 512
            elif line.startswith("pwdLastSet:"):
                try:
                    cur_u["pwd_last_set"] = int(line.split(":", 1)[1].strip())
                except Exception:
                    cur_u["pwd_last_set"] = 0
        if cur_u.get("username"):
            users_to_check.append(cur_u)

        from api.routers.registration import dispatch_email, dispatch_sms

        reminders_sent = 0
        notified_users = []

        for u in users_to_check:
            username = u["username"]
            info = get_user_password_info(username)
            if info.get("never_expires") or info.get("is_expired"):
                continue

            days_rem = info.get("days_remaining")
            if days_rem is None or days_rem <= 0:
                continue

            # Determine matching threshold: 14, 7, 1
            threshold = None
            if 7.0 < days_rem <= 14.0:
                threshold = 14
            elif 1.0 < days_rem <= 7.0:
                threshold = 7
            elif 0.0 < days_rem <= 1.0:
                threshold = 1

            if threshold is None:
                continue

            pwd_cycle = float(info.get("pwd_last_set") or 0)

            # Check if reminder was already sent for this threshold in this cycle
            cursor.execute("""
                SELECT id FROM password_expiry_reminders
                WHERE username = ? AND threshold_days = ? AND pwd_last_set = ?
            """, (username, threshold, pwd_cycle))
            if cursor.fetchone():
                continue

            days_text = f"{int(round(days_rem))} day" if int(round(days_rem)) == 1 else f"{int(round(days_rem))} days"
            realm = get_primary_realm()
            reminder_msg = (
                f"Security Notice: Your ZclockID corporate password for account '{username}' will expire in {days_text}. "
                f"Please update your password before expiry at https://{realm.lower()}/password-reset.html#change"
            )

            channel = "none"
            dispatched = False

            # Send Email if available
            to_email = u.get("email")
            if to_email:
                subject = f"Action Required: Password Expiring in {days_text} - {username}"
                ok_mail, _ = dispatch_email(to_email, subject, reminder_msg, reg_settings)
                if ok_mail:
                    channel = "email"
                    dispatched = True

            # Send SMS if available
            to_mobile = u.get("mobile")
            if to_mobile:
                ok_sms, _ = dispatch_sms(to_mobile, reminder_msg, reg_settings)
                if ok_sms:
                    channel = "sms" if not dispatched else "email+sms"
                    dispatched = True

            if not dispatched:
                # If neither contact exists, record simulated notification
                logger.info("[EXPIRY-REMINDER-SIMULATED] %s: %s", username, reminder_msg)
                channel = "simulated"
                dispatched = True

            if dispatched:
                cursor.execute("""
                    INSERT INTO password_expiry_reminders (
                        username, threshold_days, pwd_last_set, sent_at, channel, status
                    ) VALUES (?, ?, ?, ?, ?, 'SENT')
                """, (username, threshold, pwd_cycle, now, channel))
                conn.commit()

                log_audit("PASSWORD_EXPIRY_REMINDER_SENT", "system", username, "SUCCESS", {
                    "threshold_days": threshold,
                    "remaining_days": round(days_rem, 1),
                    "channel": channel
                })
                reminders_sent += 1
                notified_users.append({"username": username, "threshold": threshold, "channel": channel})

        conn.close()
        return {
            "status": "completed",
            "reminders_sent": reminders_sent,
            "notified_users": notified_users
        }
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        except Exception:
            pass


_worker_thread = None
_worker_lock = threading.Lock()

def _reminder_worker_loop():
    logger.info("Password Expiry Reminder worker started.")
    time.sleep(5)
    try:
        ensure_selfreg_group_and_pso()
    except Exception as e:
        logger.warning(f"Initial PSO ensure warning: {e}")

    while True:
        try:
            run_password_expiry_reminders()
        except Exception as e:
            logger.warning(f"Password expiry reminder job execution error: {e}")
        time.sleep(3600)  # check every hour


def start_password_expiry_reminder_worker():
    """Starts the background worker thread for PSO management and daily expiry reminders."""
    global _worker_thread
    with _worker_lock:
        if _worker_thread is None or not _worker_thread.is_alive():
            _worker_thread = threading.Thread(
                target=_reminder_worker_loop,
                daemon=True,
                name="PasswordExpiryReminderWorker"
            )
            _worker_thread.start()
            logger.info("Launched PasswordExpiryReminderWorker daemon thread.")
