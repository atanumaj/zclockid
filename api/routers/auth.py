"""
ZclockID Authentication & Setup Wizard Router
"""

import os
import re
import time
import secrets
import sqlite3
import logging
from fastapi import APIRouter, HTTPException, status, Header, Request
from typing import Optional

from api.core.config import (
    DB_PATH,
    SETUP_LOCK_FILE,
    AD_CREDS_FILE,
    APP_VERSION
)
from api.core.security import hash_password, verify_password, get_ad_creds
from api.services.system_service import run_cmd, log_audit
from api.services.security_service import get_client_ip, get_security_settings
from api.schemas.auth_schema import (
    SetupProvisionRequest,
    LoginRequest,
    ChangePasswordRequest,
    BreakGlassUpdateRequest
)

router = APIRouter(prefix="/api/v1", tags=["Authentication & Setup"])

@router.get("/setup/status")
def get_setup_status():
    is_locked = SETUP_LOCK_FILE.exists()
    has_smb = os.path.exists("/etc/samba/smb.conf")
    has_admin = False
    try:
        if DB_PATH.exists():
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM admin_users")
            count = cursor.fetchone()[0]
            has_admin = (count > 0)
            conn.close()
    except Exception:
        has_admin = False

    is_configured = is_locked and has_smb and has_admin
    return {
        "is_configured": is_configured,
        "setup_lock": is_locked,
        "has_admin": has_admin,
        "hostname": os.uname().nodename,
        "version": APP_VERSION
    }

@router.post("/setup/provision")
def execute_initial_provisioning(req: SetupProvisionRequest):
    realm = req.realm.upper()
    domain = req.domain_netbios.upper()

    # Save credentials securely
    AD_CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(AD_CREDS_FILE, "w") as f:
        f.write(f"AD_ADMIN={req.ad_admin_user}\nAD_PASS={req.ad_admin_password}\n")
    os.chmod(AD_CREDS_FILE, 0o600)

    # 1. Update System Hostname if specified
    current_hostname = os.uname().nodename
    if req.system_hostname and req.system_hostname.strip():
        new_hn = req.system_hostname.strip().lower()
        if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", new_hn):
            raise HTTPException(
                status_code=400,
                detail="Invalid hostname. Must contain only lowercase alphanumeric characters and hyphens (up to 63 characters), and cannot start or end with a hyphen."
            )
        run_cmd(["hostnamectl", "set-hostname", new_hn])
        current_hostname = new_hn

        # Update /etc/hosts for correct local FQDN resolution
        if os.path.exists("/etc/hosts"):
            try:
                with open("/etc/hosts", "r") as f:
                    hosts_content = f.read()
                fqdn_str = f"{new_hn}.{realm.lower()}\t{new_hn}"
                if "127.0.1.1" in hosts_content:
                    hosts_content = re.sub(r'127\.0\.1\.1\s+.*', f'127.0.1.1\t{fqdn_str}', hosts_content)
                else:
                    hosts_content += f"\n127.0.1.1\t{fqdn_str}\n"
                with open("/tmp/hosts.tmp", "w") as f:
                    f.write(hosts_content)
                run_cmd(["cp", "/tmp/hosts.tmp", "/etc/hosts"])
            except Exception as e:
                logging.getLogger("uvicorn.error").warning(f"Could not update /etc/hosts: {e}")

        # Update appliance self-signed TLS cert with new hostname CN
        if os.path.exists("/etc/zclockid/certs"):
            fqdn = f"{new_hn}.{realm.lower()}"
            run_cmd([
                "openssl", "req", "-x509", "-nodes", "-days", "1825", "-newkey", "rsa:2048",
                "-keyout", "/etc/zclockid/certs/appliance.key",
                "-out", "/etc/zclockid/certs/appliance.crt",
                "-subj", f"/CN={fqdn}/O=ZclockID Enterprise/OU=Appliance"
            ])
            run_cmd(["chmod", "600", "/etc/zclockid/certs/appliance.key"])
            run_cmd(["systemctl", "reload", "nginx"])

    # 2. Create Web Administrator User
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    hashed_pw, salt = hash_password(req.admin_password)
    cursor.execute("""
        INSERT INTO admin_users (username, salt, password_hash, email, created_at, last_login)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET salt=excluded.salt, password_hash=excluded.password_hash
    """, (req.admin_username, salt, hashed_pw, req.admin_email, time.time(), time.time()))
    conn.commit()
    conn.close()

    # 3. Backup old smb.conf and purge stale database directories
    if os.path.exists("/etc/samba/smb.conf"):
        run_cmd(["cp", "/etc/samba/smb.conf", f"/etc/samba/smb.conf.bak-{int(time.time())}"])
        run_cmd(["rm", "-f", "/etc/samba/smb.conf"])

    if req.mode == "new_domain":
        run_cmd(["rm", "-rf", "/var/lib/samba/private"])
        run_cmd(["mkdir", "-p", "/var/lib/samba/private"])
        run_cmd(["chmod", "700", "/var/lib/samba/private"])
        run_cmd(["rm", "-rf", "/var/lib/samba/bind-dns"])
        run_cmd(["mkdir", "-p", "/var/lib/samba/bind-dns"])
        run_cmd(["rm", "-rf", "/var/lib/samba/sysvol"])
        run_cmd(["mkdir", "-p", "/var/lib/samba/sysvol"])

    provision_output = ""
    # Ensure samba-ad-provision schema files are installed if absent (auto-heal for Ubuntu 24.04/26.04)
    if not os.path.exists("/usr/share/samba/setup/ad-schema") or not os.path.exists("/usr/share/samba/setup/provision.smb.conf.dc"):
        run_cmd(["apt-get", "update", "-y"])
        run_cmd(["apt-get", "install", "-y", "samba-ad-provision", "ldb-tools", "python3-setproctitle"])

    # 4. Provisioning or Joining Domain
    if req.mode == "new_domain":
        cmd = [
            "samba-tool", "domain", "provision",
            f"--realm={realm}",
            f"--domain={domain}",
            "--server-role=dc",
            "--dns-backend=BIND9_DLZ",
            f"--host-name={current_hostname}",
            f"--adminpass={req.ad_admin_password}",
            "--use-rfc2307"
        ]
        code, stdout, stderr = run_cmd(cmd, timeout=180)
        provision_output = stdout + stderr
        if code != 0 and "not installed" not in stderr:
            raise HTTPException(status_code=500, detail=f"Samba AD provisioning failed: {stderr or stdout}")
    else:
        cmd = [
            "samba-tool", "domain", "join",
            realm, "DC",
            f"-U{req.ad_admin_user}",
            f"--password={req.ad_admin_password}",
            "--dns-backend=BIND9_DLZ"
        ]
        code, stdout, stderr = run_cmd(cmd, timeout=180)
        provision_output = stdout + stderr
        if code != 0 and "not installed" not in stderr:
            raise HTTPException(status_code=500, detail=f"Joining domain failed: {stderr or stdout}")

    # 4. Configure BIND9 with Samba DLZ include
    named_conf_local = "/etc/bind/named.conf.local"
    dlz_block = """// Load Samba DLZ dynamically for Active Directory DNS
include "/var/lib/samba/bind-dns/named.conf";
"""
    try:
        with open(named_conf_local, "w") as f:
            f.write(dlz_block)
        run_cmd(["chown", "-R", "root:bind", "/var/lib/samba/bind-dns"])
        run_cmd(["chmod", "750", "/var/lib/samba/bind-dns"])
        if os.path.exists("/var/lib/samba/bind-dns/dns"):
            run_cmd(["chmod", "-R", "770", "/var/lib/samba/bind-dns/dns"])
    except Exception:
        pass

    # Copy generated Kerberos config
    if os.path.exists("/var/lib/samba/private/krb5.conf"):
        run_cmd(["cp", "-f", "/var/lib/samba/private/krb5.conf", "/etc/krb5.conf"])

    # 5. Start and enable services
    run_cmd(["systemctl", "unmask", "samba-ad-dc"])
    run_cmd(["systemctl", "enable", "samba-ad-dc"])
    run_cmd(["systemctl", "restart", "samba-ad-dc"])
    run_cmd(["systemctl", "restart", "bind9"])
    run_cmd(["systemctl", "enable", "zclock-sysvold"])
    run_cmd(["systemctl", "restart", "zclock-sysvold"])

    # 6. Create setup lock file
    SETUP_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SETUP_LOCK_FILE, "w") as f:
        f.write(f"PROVISIONED_AT={time.time()}\nREALM={realm}\nDOMAIN={domain}\nMODE={req.mode}\nHOSTNAME={current_hostname}\n")

    # Update default domain in self registration settings to match newly provisioned realm
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE self_registration_settings 
            SET default_domain = ?, smtp_from = ? 
            WHERE id = 1
        """, (realm.lower(), f"no-reply@{realm.lower()}"))
        conn.commit()
        conn.close()
    except Exception:
        pass

    log_audit("APPLIANCE_PROVISIONED", req.admin_username, realm, "SUCCESS", {
        "mode": req.mode,
        "domain": domain,
        "hostname": current_hostname
    })

    return {
        "status": "success",
        "realm": realm,
        "domain": domain,
        "hostname": current_hostname,
        "message": f"ZclockID provisioned successfully in {req.mode} mode on host '{current_hostname}'.",
        "log": provision_output[:1000]
    }

@router.post("/auth/login")
def login(req: LoginRequest, request: Request):
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:250]
    settings = get_security_settings()

    # Brute-force rate limiting & lockout check
    max_failed = settings.get("max_failed_logins", 5)
    lockout_min = settings.get("lockout_duration_min", 15)
    cutoff = time.time() - (lockout_min * 60)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) FROM failed_login_attempts
        WHERE (ip_address = ? OR username = ?) AND timestamp > ?
    """, (client_ip, req.username, cutoff))
    recent_failures = cursor.fetchone()[0]

    if recent_failures >= max_failed:
        conn.close()
        log_audit("LOGIN_LOCKED_OUT", req.username, "web_console", "BLOCKED", {
            "ip": client_ip, "failures": recent_failures, "lockout_min": lockout_min
        })
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Security Baseline Lockout: Too many failed login attempts ({recent_failures}). This account and IP are locked for {lockout_min} minutes."
        )

    cursor.execute("SELECT password_hash, salt FROM admin_users WHERE username = ?", (req.username,))
    row = cursor.fetchone()

    authenticated = False
    is_local = False
    role = "readonly"

    # 1. Local admin authentication check (Break-Glass admin fallback)
    if row:
        stored_hash, salt = row
        if verify_password(req.password, stored_hash, salt):
            authenticated = True
            is_local = True
            from api.routers.rbac import resolve_user_role
            role, _ = resolve_user_role(req.username, is_local_admin=True)

    # 2. If not local or local failed, attempt Active Directory authentication
    if not authenticated:
        import subprocess
        env = os.environ.copy()
        env["PASSWD"] = req.password
        try:
            proc = subprocess.run(
                ["smbclient", "//127.0.0.1/netlogon", "-U", req.username, "-c", "ls"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            if proc.returncode == 0:
                authenticated = True
                is_local = False
                from api.routers.rbac import resolve_user_role
                role, _ = resolve_user_role(req.username, is_local_admin=False)
        except Exception:
            pass

    if not authenticated:
        cursor.execute("INSERT INTO failed_login_attempts (ip_address, username, timestamp) VALUES (?, ?, ?)",
                       (client_ip, req.username, time.time()))
        conn.commit()
        conn.close()
        log_audit("LOGIN_FAILED", req.username, "web_console", "FAILED", {"detail": "Invalid credentials", "ip": client_ip})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    # Successful login: clear failed attempts
    cursor.execute("DELETE FROM failed_login_attempts WHERE ip_address = ? OR username = ?", (client_ip, req.username))

    token = secrets.token_hex(32)
    now = time.time()
    max_life_hours = settings.get("session_max_lifetime_hours", 8)
    expires_at = now + (max_life_hours * 3600)
    cursor.execute("""
        INSERT INTO sessions (token, username, role, ip_address, user_agent, created_at, last_active, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (token, req.username, role, client_ip, user_agent, now, now, expires_at))
    if is_local:
        cursor.execute("UPDATE admin_users SET last_login = ? WHERE username = ?", (now, req.username))
    conn.commit()
    conn.close()

    log_audit("ADMIN_LOGIN", req.username, "web_console", "SUCCESS", {"role": role, "is_ad_user": not is_local, "ip": client_ip})
    return {
        "status": "success",
        "token": token,
        "access_token": token,
        "token_type": "bearer",
        "username": req.username,
        "role": role,
        "is_ad_user": not is_local,
        "expires_in": max_life_hours * 3600,
        "idle_timeout_min": settings.get("session_idle_timeout_min", 15)
    }

@router.post("/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if not authorization:
        return {"status": "success"}
    token = authorization.replace("Bearer ", "").strip()
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    except Exception:
        pass
    return {"status": "success", "message": "Logged out successfully."}

def get_session_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    token = authorization.replace("Bearer ", "").strip()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT username, role, expires_at, last_active, created_at FROM sessions WHERE token = ?", (token,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid.")

    now = time.time()
    if row["expires_at"] < now:
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has expired. Please log in again.")

    # Idle timeout validation
    settings = get_security_settings()
    idle_timeout_min = settings.get("session_idle_timeout_min", 15)
    last_act = row["last_active"] or row["created_at"] or now

    if idle_timeout_min > 0 and (now - last_act) > (idle_timeout_min * 60):
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Session expired due to {idle_timeout_min} minutes of inactivity. Please sign in again."
        )

    # Throttled update of last_active (every 30 seconds)
    if (now - last_act) > 30:
        cursor.execute("UPDATE sessions SET last_active = ? WHERE token = ?", (now, token))
        conn.commit()

    conn.close()
    return dict(row)

@router.get("/auth/profile")
def get_user_profile(authorization: Optional[str] = Header(None)):
    """Returns current authenticated administrator profile and emergency break-glass details."""
    session_user = get_session_user(authorization)
    username = session_user["username"]
    role = session_user["role"]

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT username, email, last_login, created_at FROM admin_users WHERE username = ?", (username,))
    local_row = cursor.fetchone()

    cursor.execute("SELECT username, email, last_login FROM admin_users WHERE username = 'admin'")
    bg_admin_row = cursor.fetchone()
    conn.close()

    is_local = (local_row is not None)

    ad_groups = []
    ad_display_name = ""
    ad_mail = ""
    if not is_local:
        from api.routers.rbac import get_user_ad_groups
        ad_groups = get_user_ad_groups(username)
        from api.core.config import SAMBA_LDB_PATH
        code, stdout, _ = run_cmd([
            "ldbsearch", "-H", str(SAMBA_LDB_PATH),
            f"(&(objectClass=user)(sAMAccountName={username}))",
            "displayName", "mail"
        ], timeout=5)
        if code == 0 and stdout:
            for line in stdout.splitlines():
                if line.startswith("displayName:"):
                    ad_display_name = line.split(":", 1)[1].strip()
                elif line.startswith("mail:"):
                    ad_mail = line.split(":", 1)[1].strip()

    return {
        "username": username,
        "role": role,
        "is_ad_user": not is_local,
        "email": local_row["email"] if is_local else ad_mail,
        "display_name": ad_display_name if not is_local else "Local Administrator",
        "ad_groups": ad_groups,
        "break_glass_admin": {
            "username": "admin",
            "email": bg_admin_row["email"] if bg_admin_row else "",
            "last_login": bg_admin_row["last_login"] if bg_admin_row else None
        } if bg_admin_row else None
    }

@router.post("/auth/change-password")
def change_password(req: ChangePasswordRequest, authorization: Optional[str] = Header(None)):
    """Changes the password for the currently logged-in account (local or AD)."""
    session_user = get_session_user(authorization)
    username = session_user["username"]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt FROM admin_users WHERE username = ?", (username,))
    local_row = cursor.fetchone()

    if local_row:
        # Local Break-Glass Account
        stored_hash, salt = local_row
        if not verify_password(req.current_password, stored_hash, salt):
            conn.close()
            raise HTTPException(status_code=400, detail="Current password verification failed.")

        new_hash, new_salt = hash_password(req.new_password)
        cursor.execute("UPDATE admin_users SET salt = ?, password_hash = ? WHERE username = ?",
                       (new_salt, new_hash, username))
        conn.commit()
        conn.close()
        log_audit("LOCAL_ADMIN_PASSWORD_CHANGED", username, username, "SUCCESS", {})
        return {"status": "success", "message": "Break-glass admin password updated successfully."}

    conn.close()

    # Active Directory Domain Account
    import subprocess
    env = os.environ.copy()
    env["PASSWD"] = req.current_password
    proc = subprocess.run(
        ["smbclient", "//127.0.0.1/netlogon", "-U", username, "-c", "ls"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
    )
    if proc.returncode != 0:
        raise HTTPException(status_code=400, detail="Current domain password verification failed.")

    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd([
        "samba-tool", "user", "setpassword", username,
        f"--newpassword={req.new_password}",
        f"-U{admin_user}", f"--password={admin_pass}"
    ], timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to set Active Directory password: {stderr or stdout}")

    log_audit("AD_USER_PASSWORD_CHANGED", username, username, "SUCCESS", {})
    return {"status": "success", "message": f"Active Directory password for '{username}' updated successfully."}

@router.post("/auth/break-glass")
def update_break_glass_admin(req: BreakGlassUpdateRequest, authorization: Optional[str] = Header(None)):
    """Allows authenticated Full Administrators to update the offline emergency break-glass account."""
    session_user = get_session_user(authorization)
    if session_user["role"] != "fulladmin":
        raise HTTPException(status_code=403, detail="Only Full Administrators can configure the break-glass account.")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    updates = []
    params = []
    if req.new_password:
        new_hash, new_salt = hash_password(req.new_password)
        updates.extend(["salt = ?", "password_hash = ?"])
        params.extend([new_salt, new_hash])
    if req.email is not None:
        updates.append("email = ?")
        params.append(req.email.strip())

    if not updates:
        conn.close()
        return {"status": "success", "message": "No changes requested."}

    params.append("admin")
    cursor.execute(f"UPDATE admin_users SET {', '.join(updates)} WHERE username = ?", tuple(params))
    conn.commit()
    conn.close()

    log_audit("BREAK_GLASS_SETTINGS_UPDATED", session_user["username"], "admin", "SUCCESS", {
        "password_changed": bool(req.new_password),
        "email_changed": bool(req.email)
    })
    return {"status": "success", "message": "Break-glass emergency admin settings updated successfully."}

