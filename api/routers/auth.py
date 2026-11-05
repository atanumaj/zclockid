"""
ZclockID Authentication & Setup Wizard Router
"""

import os
import time
import secrets
import sqlite3
from fastapi import APIRouter, HTTPException, status, Header
from typing import Optional

from api.core.config import (
    DB_PATH,
    SETUP_LOCK_FILE,
    AD_CREDS_FILE,
    APP_VERSION
)
from api.core.security import hash_password, verify_password
from api.services.system_service import run_cmd, log_audit
from api.schemas.auth_schema import SetupProvisionRequest, LoginRequest

router = APIRouter(prefix="/api/v1", tags=["Authentication & Setup"])

@router.get("/setup/status")
def get_setup_status():
    is_locked = SETUP_LOCK_FILE.exists()
    has_smb = os.path.exists("/etc/samba/smb.conf")
    is_configured = is_locked and has_smb
    return {
        "is_configured": is_configured,
        "setup_lock": is_locked,
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

    # 1. Create Web Administrator User
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

    # 2. Backup old smb.conf and purge stale database directories
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
    # 3. Provisioning or Joining Domain
    if req.mode == "new_domain":
        cmd = [
            "samba-tool", "domain", "provision",
            f"--realm={realm}",
            f"--domain={domain}",
            "--server-role=dc",
            "--dns-backend=BIND9_DLZ",
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
        f.write(f"PROVISIONED_AT={time.time()}\nREALM={realm}\nDOMAIN={domain}\nMODE={req.mode}\n")

    log_audit("APPLIANCE_PROVISIONED", req.admin_username, realm, "SUCCESS", {"mode": req.mode, "domain": domain})

    return {
        "status": "success",
        "realm": realm,
        "domain": domain,
        "message": f"ZclockID provisioned successfully in {req.mode} mode.",
        "log": provision_output[:1000]
    }

@router.post("/auth/login")
def login(req: LoginRequest):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
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
        conn.close()
        log_audit("LOGIN_FAILED", req.username, "web_console", "FAILED", {"detail": "Invalid credentials"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    token = secrets.token_hex(32)
    now = time.time()
    expires_at = now + 86400  # 24 hours
    cursor.execute("INSERT INTO sessions (token, username, role, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                   (token, req.username, role, now, expires_at))
    if is_local:
        cursor.execute("UPDATE admin_users SET last_login = ? WHERE username = ?", (now, req.username))
    conn.commit()
    conn.close()

    log_audit("ADMIN_LOGIN", req.username, "web_console", "SUCCESS", {"role": role, "is_ad_user": not is_local})
    return {
        "status": "success",
        "token": token,
        "access_token": token,
        "token_type": "bearer",
        "username": req.username,
        "role": role,
        "is_ad_user": not is_local,
        "expires_in": 86400
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

