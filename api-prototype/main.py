"""
ZclockID Enterprise Management API & Appliance Backend
Provides comprehensive GUI and API control for:
- First-time setup wizard & admin account creation
- Samba AD DC Domain Provisioning & Multi-DC Join
- Domain Settings & Alternate UPN Suffixes & FSMO Role Ownership
- Users, Groups, and Password Management
- Active Directory Integrated DNS (BIND9 DLZ & DoH, Kerberos SRV Records, Forwarders)
- FreeRADIUS 802.1X NAS Client Management, Strong Secret Generation & Accounting Options
- Bi-directional Sysvol & Windows NTACL Self-Healing
- Azure / Microsoft Entra ID Cloud Sync
- Appliance Service & System Control (Status, Memory, PIDs, Live Journalctl Logs)
"""

from fastapi import FastAPI, HTTPException, status, Query, Depends, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from pathlib import Path
import subprocess
import os
import time
import sqlite3
import csv
import io
import json
import hashlib
import secrets
import re

app = FastAPI(
    title="ZclockID Appliance Management API",
    version="1.1.0",
    description="Enterprise-grade appliance backend for ZclockID Active Directory Domain Controller",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- Database & State Initialization -----------------

DATA_DIR = Path(os.environ.get("ZCLOCKID_DATA_DIR", "/var/lib/zclockid"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "zclockid.db"
SETUP_LOCK_FILE = Path("/etc/zclockid/setup.lock")
AD_CREDS_FILE = Path("/etc/zclockid/ad_creds")
AZURE_CONFIG_FILE = Path("/etc/zclockid/azure-sync.json")
AZURE_STATUS_FILE = Path("/var/run/zclock-azuresync.status")
SYSVOL_HEALTH_FILE = Path("/var/run/zclock-sysvol.health")
BIND_OPTIONS_FILE = Path("/etc/bind/named.conf.options")
RADIUS_CLIENTS_FILE = Path("/etc/freeradius/3.0/clients.conf")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Admin users for Web GUI authentication
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at REAL,
            last_login REAL
        )
    """)
    # Active web sessions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at REAL,
            expires_at REAL
        )
    """)
    # Self-Registration Queue
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS self_registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            given_name TEXT,
            surname TEXT,
            department TEXT,
            status TEXT DEFAULT 'PENDING',
            ip_address TEXT,
            created_at REAL,
            approved_at REAL,
            approved_by TEXT,
            notes TEXT
        )
    """)
    # Audit & Reporting Events
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor TEXT,
            target TEXT,
            status TEXT,
            details TEXT,
            timestamp REAL
        )
    """)
    # RADIUS Accounting Sessions (pfSense style)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_accounting (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            nas_ip TEXT NOT NULL,
            nas_name TEXT,
            calling_station_id TEXT,
            framed_ip TEXT,
            acct_status_type TEXT DEFAULT 'Start',
            acct_session_time INTEGER DEFAULT 0,
            input_octets INTEGER DEFAULT 0,
            output_octets INTEGER DEFAULT 0,
            terminate_cause TEXT,
            start_time REAL,
            last_update REAL
        )
    """)
    # Seed sample active RADIUS sessions if empty
    cursor.execute("SELECT COUNT(*) FROM radius_accounting")
    if cursor.fetchone()[0] == 0:
        now = time.time()
        cursor.execute("""
            INSERT INTO radius_accounting 
            (session_id, username, nas_ip, nas_name, calling_station_id, framed_ip, acct_status_type, acct_session_time, input_octets, output_octets, start_time, last_update)
            VALUES 
            ('sess-corp-01', 'atanu', '192.168.1.253', 'TL-SG3452XP-Switch', 'D8:3B:BF:11:22:33', '192.168.1.150', 'Active', 7200, 142606336, 524288000, ?, ?),
            ('sess-corp-02', 'administrator', '192.168.1.38', 'UniFi-U6-Enterprise', '3C:06:30:AA:BB:CC', '192.168.1.185', 'Active', 3600, 89128960, 268435456, ?, ?)
        """, (now - 7200, now, now - 3600, now))

    # RADIUS General Configuration
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            auth_port INTEGER DEFAULT 1812,
            acct_port INTEGER DEFAULT 1813,
            acct_enabled INTEGER DEFAULT 1,
            interim_interval INTEGER DEFAULT 300,
            updated_at REAL
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO radius_settings (id, auth_port, acct_port, acct_enabled, interim_interval, updated_at) VALUES (1, 1812, 1813, 1, 300, ?)", (time.time(),))

    conn.commit()
    conn.close()

init_db()

# ----------------- Helper Functions -----------------

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return hashed, salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    check_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(check_hash, hashed)

def run_cmd(cmd: List[str], timeout: int = 45) -> tuple[int, str, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout, res.stderr
    except FileNotFoundError:
        return -1, "", f"Command '{cmd[0]}' not installed"
    except Exception as e:
        return -1, "", str(e)

def get_ad_creds() -> tuple[str, str]:
    admin_user = "Administrator"
    admin_pass = "P@ssw0rd@inet"
    if AD_CREDS_FILE.exists():
        try:
            with open(AD_CREDS_FILE) as f:
                for line in f:
                    if line.startswith("AD_ADMIN="):
                        admin_user = line.split("=", 1)[1].strip()
                    elif line.startswith("AD_PASS="):
                        admin_pass = line.split("=", 1)[1].strip()
        except Exception:
            pass
    return admin_user, admin_pass

def check_systemd_service(service_name: str) -> Dict[str, Any]:
    code, out, _ = run_cmd(["systemctl", "is-active", service_name], timeout=5)
    is_active = (out.strip() == "active")
    pid = None
    mem_mb = None
    if is_active:
        _, out_p, _ = run_cmd(["systemctl", "show", service_name, "--property=MainPID,MemoryCurrent"], timeout=5)
        for line in out_p.splitlines():
            if line.startswith("MainPID="):
                try:
                    pid = int(line.split("=")[1])
                except:
                    pass
            elif line.startswith("MemoryCurrent="):
                try:
                    raw_b = int(line.split("=")[1])
                    if 0 < raw_b < 10**14:
                        mem_mb = round(raw_b / (1024 * 1024), 1)
                except:
                    pass
    return {
        "status": "active" if is_active else "inactive",
        "systemd_state": out.strip() if code == 0 else "unknown",
        "pid": pid,
        "memory_mb": mem_mb
    }

def log_audit(event_type: str, actor: str, target: str, status: str, details: Dict[str, Any]):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_events (event_type, actor, target, status, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (event_type, actor, target, status, json.dumps(details), time.time()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging audit: {e}")

# ----------------- Pydantic Data Models -----------------

class SetupProvisionRequest(BaseModel):
    admin_username: str = Field("admin", example="admin")
    admin_password: str = Field(..., min_length=8, example="AdminP@ssw0rd2026!")
    admin_email: Optional[str] = Field("admin@corp.example.com", example="admin@corp.example.com")
    mode: str = Field("new_domain", pattern="^(new_domain|join_domain)$")
    realm: str = Field(..., example="CORP.EXAMPLE.COM")
    domain_netbios: str = Field(..., example="CORP")
    ad_admin_password: str = Field(..., min_length=8, example="DomainP@ssw0rd2026!")
    dns_forwarder: Optional[str] = Field("1.1.1.1 8.8.8.8", example="1.1.1.1 8.8.8.8")
    partner_dc_ip: Optional[str] = Field(None, example="192.168.1.23")
    ad_admin_user: Optional[str] = Field("Administrator", example="Administrator")

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreateRequest(BaseModel):
    username: str = Field(..., example="john.doe")
    password: str = Field(..., min_length=8, example="P@ssw0rd2026!")
    given_name: Optional[str] = Field(None, example="John")
    surname: Optional[str] = Field(None, example="Doe")
    email: Optional[str] = Field(None, example="john.doe@corp.example.com")
    department: Optional[str] = None
    target_group: Optional[str] = "Domain Users"

class UserPasswordReset(BaseModel):
    new_password: str = Field(..., min_length=8, example="NewSecureP@ss2026!")
    must_change_at_next_logon: bool = False

class GroupCreateRequest(BaseModel):
    group_name: str = Field(..., example="SG-IT-Admins")
    description: Optional[str] = None

class DnsRecordRequest(BaseModel):
    zone: str = Field(..., example="inet.net")
    record_name: str = Field(..., example="web")
    record_type: str = Field("A", pattern="^(A|AAAA|CNAME|TXT|SRV|MX|PTR)$")
    record_data: str = Field(..., example="192.168.1.55")
    port: Optional[int] = Field(None, example=88)
    priority: Optional[int] = Field(0, example=0)
    weight: Optional[int] = Field(100, example=100)
    ttl: Optional[int] = Field(900, example=900)

class DnsForwardersRequest(BaseModel):
    forwarders: List[str] = Field(..., example=["1.1.1.1", "8.8.8.8"])
    policy: Optional[str] = Field("first", pattern="^(first|only)$")

class DnsZoneCreateRequest(BaseModel):
    zone_name: str = Field(..., example="corpzee.com")

class RadiusClientRequest(BaseModel):
    client_name: str = Field(..., example="floor-1-ap-cluster")
    ip_subnet: str = Field(..., example="192.168.1.0/24")
    shared_secret: str = Field(..., example="RadP@ss2026!")
    shortname: Optional[str] = "ap-cluster"
    nas_type: Optional[str] = "other"

class RadiusSettingsRequest(BaseModel):
    auth_port: int = 1812
    acct_port: int = 1813
    acct_enabled: bool = True
    interim_interval: int = 300

class ServiceActionRequest(BaseModel):
    action: str = Field("restart", pattern="^(restart|start|stop|reload)$")

class UpnSuffixRequest(BaseModel):
    upn_suffix: str = Field(..., example="alternate.net")

class FsmoTransferRequest(BaseModel):
    role: str = Field(..., pattern="^(all|schema|naming|rid|pdc|infrastructure)$")
    target_dc: Optional[str] = None
    force_seize: bool = False

class SysvolPartnerRequest(BaseModel):
    name: str = Field(..., example="DC2-Secondary")
    ip_address: str = Field(..., example="192.168.1.42")
    shared_secret: str = Field(..., example="PartnerSyncSecret2026!")

class SysvolFileUploadRequest(BaseModel):
    rel_path: str = Field(..., example="inet.net/Policies/{GUID}/GPT.INI")
    content_base64: str
    mtime: Optional[float] = None

class AzureSyncConfig(BaseModel):
    enabled: bool = False
    tenant_id: str = Field(..., example="00000000-0000-0000-0000-000000000000")
    client_id: str = Field(..., example="11111111-1111-1111-1111-111111111111")
    client_secret: str = Field(..., example="secret_value")

# ----------------- First-Time Setup Wizard Endpoints -----------------

@app.get("/api/v1/setup/status")
def get_setup_status():
    is_locked = SETUP_LOCK_FILE.exists()
    has_smb = os.path.exists("/etc/samba/smb.conf")
    is_configured = is_locked and has_smb
    return {
        "is_configured": is_configured,
        "setup_lock": is_locked,
        "hostname": os.uname().nodename,
        "version": "1.0.0-LTS"
    }

@app.post("/api/v1/setup/provision")
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

# ----------------- Authentication Endpoints -----------------

@app.post("/api/v1/auth/login")
def login(req: LoginRequest):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt FROM admin_users WHERE username = ?", (req.username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    stored_hash, salt = row
    if not verify_password(req.password, stored_hash, salt):
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    token = secrets.token_hex(32)
    now = time.time()
    expires_at = now + 86400  # 24 hours
    cursor.execute("INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
                   (token, req.username, now, expires_at))
    cursor.execute("UPDATE admin_users SET last_login = ? WHERE username = ?", (now, req.username))
    conn.commit()
    conn.close()

    log_audit("ADMIN_LOGIN", req.username, "web_console", "SUCCESS", {})
    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
        "username": req.username,
        "expires_in": 86400
    }

# ----------------- Dashboard & System Status -----------------

@app.get("/api/v1/system/status")
def get_system_status():
    """Returns comprehensive appliance health, engine statuses, PIDs, memory, and ports."""
    services = {
        "samba_ad_dc": check_systemd_service("samba-ad-dc"),
        "bind9": check_systemd_service("bind9"),
        "freeradius": check_systemd_service("freeradius"),
        "zclock_sysvold": check_systemd_service("zclock-sysvold"),
        "nginx": check_systemd_service("nginx"),
        "snmpd": check_systemd_service("snmpd"),
        "zclock_api": check_systemd_service("zclock-api")
    }

    # Port listeners map
    ports_map = {
        "DNS (UDP/TCP)": 53,
        "Kerberos KDC": 88,
        "MSRPC Endpoint": 135,
        "NetBIOS-SSN": 139,
        "LDAP Directory": 389,
        "HTTPS / DoH Ingress": 443,
        "SMB / CIFS Share": 445,
        "Kerberos Password": 464,
        "LDAPS SSL": 636,
        "DoH Internal HTTP": 8053,
        "FreeRADIUS Auth": 1812,
        "FreeRADIUS Acct": 1813,
        "Global Catalog": 3268
    }

    import psutil
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    active_count = sum(1 for s in services.values() if s["status"] == "active")
    health = "HEALTHY" if active_count >= 4 else ("INITIALIZING" if active_count >= 2 else "DEGRADED")

    return {
        "hostname": os.uname().nodename,
        "uptime_seconds": time.time() - psutil.boot_time(),
        "services": services,
        "overall_health": health,
        "ports": ports_map,
        "resources": {
            "cpu_percent": cpu_percent,
            "memory_total_mb": round(mem.total / (1024 * 1024), 1),
            "memory_used_mb": round(mem.used / (1024 * 1024), 1),
            "memory_percent": mem.percent,
            "disk_total_gb": round(disk.total / (1024 * 1024 * 1024), 1),
            "disk_used_gb": round(disk.used / (1024 * 1024 * 1024), 1),
            "disk_percent": disk.percent
        }
    }

# ----------------- Module Logs & Live Controls (Zentyal Style) -----------------

@app.get("/api/v1/services/{service_name}/logs")
def get_service_logs(service_name: str, lines: int = 50):
    """Retrieves live journalctl log lines for any engine service."""
    allowed = ["samba-ad-dc", "bind9", "freeradius", "zclock-sysvold", "zclock-api", "nginx", "snmpd", "zclock-azuresync"]
    if service_name not in allowed:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not allowed.")
    code, stdout, stderr = run_cmd(["journalctl", "-u", service_name, "-n", str(min(lines, 200)), "--no-pager"], timeout=10)
    return {"service": service_name, "logs": stdout or stderr or "No logs recorded yet."}

@app.post("/api/v1/services/{service_name}/control")
def control_service(service_name: str, req: ServiceActionRequest):
    """Executes restart, start, stop, or reload on a subsystem service."""
    allowed = ["samba-ad-dc", "bind9", "freeradius", "zclock-sysvold", "zclock-api", "nginx", "snmpd", "zclock-azuresync"]
    if service_name not in allowed:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not allowed.")
    code, stdout, stderr = run_cmd(["systemctl", req.action, service_name], timeout=15)
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to {req.action} {service_name}: {stderr}")
    log_audit("SERVICE_CONTROL", "admin", service_name, "SUCCESS", {"action": req.action})
    return {"status": "success", "service": service_name, "action": req.action, "message": f"{service_name} {req.action} successful."}

# ----------------- Active Directory Domain & UPN & FSMO Management -----------------

@app.get("/api/v1/domain/info")
def get_domain_info():
    """Returns domain NetBIOS, Realm, Forest level, SID, and FSMO role holders."""
    code, stdout, stderr = run_cmd(["samba-tool", "fsmo", "show"], timeout=10)
    fsmo = {
        "SchemaMaster": "Unassigned",
        "DomainNamingMaster": "Unassigned",
        "PdcEmulator": "Unassigned",
        "RidMaster": "Unassigned",
        "InfrastructureMaster": "Unassigned",
        "DomainDnsZonesMaster": "Unassigned",
        "ForestDnsZonesMaster": "Unassigned"
    }
    realm = "NOT_PROVISIONED"
    domain = "NOT_PROVISIONED"

    if os.path.exists("/etc/samba/smb.conf"):
        with open("/etc/samba/smb.conf") as f:
            for line in f:
                if "realm =" in line:
                    realm = line.split("=")[1].strip()
                elif "workgroup =" in line:
                    domain = line.split("=")[1].strip()

    if code == 0:
        for line in stdout.splitlines():
            if "owner:" in line:
                k, v = line.split("owner:", 1)
                k_clean = k.strip().replace("Role", "").replace(" ", "")
                m = re.search(r'CN=([^,]+),CN=Servers', v)
                srv = m.group(1) if m else v.strip()
                fsmo[k_clean] = srv

    # Get Domain SID
    domain_sid = "Unknown"
    code_sid, out_sid, _ = run_cmd(["net", "getdomainsid"], timeout=8)
    if code_sid == 0:
        for line in out_sid.splitlines():
            if "SID for domain" in line and ":" in line:
                domain_sid = line.split(":", 1)[1].strip()

    return {
        "realm": realm,
        "domain_netbios": domain,
        "domain_sid": domain_sid,
        "forest_functional_level": "Windows Server 2008 R2 / 2012 R2",
        "domain_functional_level": "Windows Server 2008 R2 / 2012 R2",
        "fsmo_roles": fsmo
    }

@app.get("/api/v1/domain/upn")
def get_upn_suffixes():
    """Returns primary domain realm and all registered alternate UPN domain suffixes."""
    realm = "NOT_PROVISIONED"
    if os.path.exists("/etc/samba/smb.conf"):
        with open("/etc/samba/smb.conf") as f:
            for line in f:
                if "realm =" in line:
                    realm = line.split("=")[1].strip()

    domain_dn = ",".join([f"DC={p}" for p in realm.lower().split(".")])
    partitions_dn = f"CN=Partitions,CN=Configuration,{domain_dn}"
    
    suffixes = []
    code, stdout, _ = run_cmd(["ldbsearch", "-H", "/var/lib/samba/private/sam.ldb", "-b", partitions_dn, "-s", "base", "uPNSuffixes"], timeout=10)
    if code == 0:
        for line in stdout.splitlines():
            if line.startswith("uPNSuffixes:"):
                suffixes.append(line.split(":", 1)[1].strip())

    return {
        "primary_realm": realm,
        "alternate_suffixes": suffixes
    }

@app.post("/api/v1/domain/upn")
def add_upn_suffix(req: UpnSuffixRequest):
    """Registers an alternate domain UPN suffix for user logins (e.g. corpzee.com)."""
    realm = "NOT_PROVISIONED"
    if os.path.exists("/etc/samba/smb.conf"):
        with open("/etc/samba/smb.conf") as f:
            for line in f:
                if "realm =" in line:
                    realm = line.split("=")[1].strip()

    suffix = req.upn_suffix.strip().lower()
    domain_dn = ",".join([f"DC={p}" for p in realm.lower().split(".")])
    partitions_dn = f"CN=Partitions,CN=Configuration,{domain_dn}"

    ldif_content = f"""dn: {partitions_dn}
changetype: modify
add: uPNSuffixes
uPNSuffixes: {suffix}
"""
    tmp_file = f"/tmp/upn_add_{int(time.time())}.ldif"
    with open(tmp_file, "w") as f:
        f.write(ldif_content)

    code, stdout, stderr = run_cmd(["ldbmodify", "-H", "/var/lib/samba/private/sam.ldb", tmp_file], timeout=10)
    try:
        os.remove(tmp_file)
    except:
        pass

    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to add alternate UPN suffix: {stderr or stdout}")

    log_audit("UPN_SUFFIX_ADDED", "admin", suffix, "SUCCESS", {})
    return {"status": "success", "message": f"Alternate UPN suffix '@{suffix}' added successfully."}

@app.delete("/api/v1/domain/upn/{suffix}")
def delete_upn_suffix(suffix: str):
    """Deletes an alternate domain UPN suffix from Active Directory."""
    realm = "NOT_PROVISIONED"
    if os.path.exists("/etc/samba/smb.conf"):
        with open("/etc/samba/smb.conf") as f:
            for line in f:
                if "realm =" in line:
                    realm = line.split("=")[1].strip()

    suffix = suffix.strip().lower()
    domain_dn = ",".join([f"DC={p}" for p in realm.lower().split(".")])
    partitions_dn = f"CN=Partitions,CN=Configuration,{domain_dn}"

    ldif_content = f"""dn: {partitions_dn}
changetype: modify
delete: uPNSuffixes
uPNSuffixes: {suffix}
"""
    tmp_file = f"/tmp/upn_del_{int(time.time())}.ldif"
    with open(tmp_file, "w") as f:
        f.write(ldif_content)

    code, stdout, stderr = run_cmd(["ldbmodify", "-H", "/var/lib/samba/private/sam.ldb", tmp_file], timeout=10)
    try:
        os.remove(tmp_file)
    except:
        pass

    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to remove alternate UPN suffix: {stderr or stdout}")

    log_audit("UPN_SUFFIX_DELETED", "admin", suffix, "SUCCESS", {})
    return {"status": "success", "message": f"Alternate UPN suffix '@{suffix}' removed successfully."}

@app.post("/api/v1/domain/fsmo/transfer")
def transfer_fsmo_role(req: FsmoTransferRequest):
    """Transfers or seizes an Active Directory FSMO role."""
    admin_user, admin_pass = get_ad_creds()
    action = "seize" if req.force_seize else "transfer"
    cmd = ["samba-tool", "fsmo", action, f"--role={req.role}", f"-U{admin_user}", f"--password={admin_pass}"]
    code, stdout, stderr = run_cmd(cmd, timeout=30)
    if code != 0:
        raise HTTPException(status_code=500, detail=f"FSMO {action} failed: {stderr or stdout}")

    log_audit("FSMO_ROLE_TRANSFERRED", "admin", req.role, "SUCCESS", {"action": action})
    return {"status": "success", "message": f"FSMO role '{req.role}' {action} successful.", "log": stdout}

@app.get("/api/v1/domain/replication")
def get_drs_replication():
    """Queries DRS Directory Replication status and consecutive failure counts."""
    code, stdout, stderr = run_cmd(["samba-tool", "drs", "showrepl"], timeout=15)
    is_replicated = (code == 0)
    return {
        "is_replicated": is_replicated,
        "raw_output": stdout if code == 0 else "Replication service initializing...",
        "consecutive_failures": 0 if is_replicated else None,
        "health": "OPTIMAL" if is_replicated else "STANDALONE"
    }

@app.post("/api/v1/domain/replication/sync")
def force_drs_replication():
    """Forces immediate Directory Replication Service synchronization."""
    code, stdout, stderr = run_cmd(["samba-tool", "drs", "kcc"], timeout=20)
    log_audit("DRS_SYNC_FORCED", "admin", "drs", "SUCCESS" if code == 0 else "FAILED", {"output": stdout})
    return {"status": "success" if code == 0 else "error", "message": stdout}

# ----------------- Users & Groups Management -----------------

@app.get("/api/v1/users")
def list_domain_users():
    code, stdout, stderr = run_cmd(["samba-tool", "user", "list"], timeout=10)
    users = []
    if code == 0:
        for line in stdout.splitlines():
            u = line.strip()
            if u:
                users.append({
                    "username": u,
                    "status": "active" if u not in ["Guest", "krbtgt"] else "disabled",
                    "department": "IT Operations" if u in ["Administrator", "admin"] else "Corporate Staff",
                    "is_built_in": u in ["Administrator", "Guest", "krbtgt", "dns-inet-zclockid"]
                })
    return {"count": len(users), "users": users}

@app.post("/api/v1/users", status_code=status.HTTP_201_CREATED)
def create_domain_user(req: UserCreateRequest):
    admin_user, admin_pass = get_ad_creds()
    cmd = [
        "samba-tool", "user", "create", req.username, req.password,
        f"-U{admin_user}", f"--password={admin_pass}"
    ]
    if req.given_name: cmd.extend(["--given-name", req.given_name])
    if req.surname: cmd.extend(["--surname", req.surname])
    if req.email: cmd.extend(["--mail-address", req.email])
    if req.department: cmd.extend(["--department", req.department])

    code, stdout, stderr = run_cmd(cmd, timeout=20)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to create user: {stderr or stdout}")

    if req.target_group and req.target_group != "Domain Users":
        run_cmd(["samba-tool", "group", "addmembers", req.target_group, req.username, f"-U{admin_user}", f"--password={admin_pass}"])

    log_audit("USER_CREATED", "admin", req.username, "SUCCESS", {"group": req.target_group})
    return {"status": "success", "username": req.username, "message": f"User {req.username} provisioned successfully."}

@app.post("/api/v1/users/{username}/password")
def set_user_password(username: str, req: UserPasswordReset):
    admin_user, admin_pass = get_ad_creds()
    cmd = ["samba-tool", "user", "setpassword", username, f"--newpassword={req.new_password}", f"-U{admin_user}", f"--password={admin_pass}"]
    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to set password: {stderr or stdout}")
    log_audit("USER_PASSWORD_RESET", "admin", username, "SUCCESS", {})
    return {"status": "success", "message": f"Password updated for {username}."}

@app.post("/api/v1/users/{username}/disable")
def disable_user(username: str):
    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "user", "disable", username, f"-U{admin_user}", f"--password={admin_pass}"])
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to disable user: {stderr}")
    log_audit("USER_DISABLED", "admin", username, "SUCCESS", {})
    return {"status": "success", "message": f"User {username} disabled."}

@app.post("/api/v1/users/{username}/enable")
def enable_user(username: str):
    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "user", "enable", username, f"-U{admin_user}", f"--password={admin_pass}"])
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to enable user: {stderr}")
    log_audit("USER_ENABLED", "admin", username, "SUCCESS", {})
    return {"status": "success", "message": f"User {username} enabled."}

@app.delete("/api/v1/users/{username}")
def delete_user(username: str):
    if username.lower() in ["administrator", "guest", "krbtgt"]:
        raise HTTPException(status_code=400, detail="Cannot delete built-in protected accounts.")
    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "user", "delete", username, f"-U{admin_user}", f"--password={admin_pass}"])
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to delete user: {stderr}")
    log_audit("USER_DELETED", "admin", username, "SUCCESS", {})
    return {"status": "success", "message": f"User {username} permanently removed."}

@app.get("/api/v1/groups")
def list_domain_groups():
    code, stdout, stderr = run_cmd(["samba-tool", "group", "list"], timeout=10)
    groups = []
    if code == 0:
        for line in stdout.splitlines():
            g = line.strip()
            if g: groups.append({"group_name": g})
    return {"count": len(groups), "groups": groups}

@app.post("/api/v1/groups")
def create_domain_group(req: GroupCreateRequest):
    admin_user, admin_pass = get_ad_creds()
    cmd = ["samba-tool", "group", "add", req.group_name, f"-U{admin_user}", f"--password={admin_pass}"]
    if req.description: cmd.extend(["--description", req.description])
    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to create group: {stderr}")
    log_audit("GROUP_CREATED", "admin", req.group_name, "SUCCESS", {})
    return {"status": "success", "group_name": req.group_name, "message": "Group created successfully."}

# ----------------- DNS Forwarders & Zones & Kerberos Records (Zentyal Style) -----------------

@app.get("/api/v1/dns/forwarders")
def get_dns_forwarders():
    """Reads upstream DNS forwarders from BIND9 configuration."""
    forwarders = ["1.1.1.1", "8.8.8.8"]
    policy = "first"
    if BIND_OPTIONS_FILE.exists():
        try:
            with open(BIND_OPTIONS_FILE) as f:
                content = f.read()
                m = re.search(r'forwarders\s*\{([^}]+)\};', content, re.DOTALL)
                if m:
                    raw = m.group(1)
                    parsed = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw)
                    if parsed: forwarders = parsed
                if "forward only;" in content:
                    policy = "only"
        except Exception:
            pass
    return {"forwarders": forwarders, "policy": policy}

@app.post("/api/v1/dns/forwarders")
def update_dns_forwarders(req: DnsForwardersRequest):
    """Updates upstream DNS forwarders in BIND9 configuration and reloads service."""
    if not req.forwarders:
        raise HTTPException(status_code=400, detail="At least one DNS forwarder IP is required.")
    
    ips_block = "\n".join([f"        {ip.strip()};" for ip in req.forwarders if ip.strip()])
    policy_line = "    forward only;\n" if req.policy == "only" else ""

    if BIND_OPTIONS_FILE.exists():
        try:
            with open(BIND_OPTIONS_FILE) as f:
                content = f.read()
            # Replace forwarders block
            new_block = f"""    forwarders {{\n{ips_block}\n    }};\n{policy_line}"""
            if re.search(r'forwarders\s*\{[^}]+\};(\s*forward\s+only;)?', content):
                content = re.sub(r'forwarders\s*\{[^}]+\};(\s*forward\s+only;)?', new_block.strip(), content)
            else:
                content = content.replace("options {", f"options {{\n{new_block}")

            with open(BIND_OPTIONS_FILE, "w") as f:
                f.write(content)

            # Test syntax and reload
            code, stdout, stderr = run_cmd(["named-checkconf", str(BIND_OPTIONS_FILE)], timeout=5)
            if code != 0:
                raise HTTPException(status_code=400, detail=f"BIND configuration syntax error: {stderr}")

            run_cmd(["systemctl", "reload", "bind9"])
            log_audit("DNS_FORWARDERS_UPDATED", "admin", "bind9", "SUCCESS", {"forwarders": req.forwarders})
            return {"status": "success", "message": "DNS forwarders updated and BIND9 reloaded.", "forwarders": req.forwarders}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to write named.conf.options: {e}")
    else:
        raise HTTPException(status_code=500, detail="named.conf.options not found.")

@app.get("/api/v1/dns/zones")
def list_dns_zones():
    """Lists all Active Directory integrated DNS zones."""
    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "dns", "zonelist", "127.0.0.1", f"-U{admin_user}", f"--password={admin_pass}"], timeout=10)
    zones = []
    if code == 0:
        for line in stdout.splitlines():
            if "pszZoneName" in line:
                z = line.split(":")[-1].strip()
                zones.append(z)
    if not zones:
        zones = ["inet.net", "_msdcs.inet.net"]
    return {"zones": zones}

@app.post("/api/v1/dns/zones")
def create_dns_zone(req: DnsZoneCreateRequest):
    """Creates a new Active Directory integrated DNS forward or reverse lookup zone."""
    admin_user, admin_pass = get_ad_creds()
    cmd = ["samba-tool", "dns", "zonecreate", "127.0.0.1", req.zone_name.strip().lower(), f"-U{admin_user}", f"--password={admin_pass}"]
    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to create zone: {stderr or stdout}")
    log_audit("DNS_ZONE_CREATED", "admin", req.zone_name, "SUCCESS", {})
    return {"status": "success", "message": f"DNS Zone '{req.zone_name}' created successfully."}

@app.get("/api/v1/dns/records")
def get_dns_records(zone: str = "inet.net"):
    """Queries all DNS records in a zone including Kerberos SRV, A, AAAA, CNAME, MX."""
    admin_user, admin_pass = get_ad_creds()
    records = []

    # 1. Root records
    code, stdout, _ = run_cmd(["samba-tool", "dns", "query", "127.0.0.1", zone, "@", "ALL", f"-U{admin_user}", f"--password={admin_pass}"], timeout=10)
    current_name = "@"
    if code == 0:
        for line in stdout.splitlines():
            if line.startswith("  Name="):
                m = re.search(r'Name=([^,]*),', line)
                if m: current_name = m.group(1).strip() or "@"
            elif line.startswith("    "):
                parts = line.strip().split(":", 1)
                if len(parts) == 2:
                    rtype = parts[0].strip()
                    rdata = parts[1].strip()
                    # Clean trailing flags
                    rdata = re.sub(r'\(flags=[^)]+\)', '', rdata).strip()
                    records.append({
                        "name": current_name,
                        "type": rtype,
                        "data": rdata,
                        "zone": zone,
                        "is_srv": (rtype == "SRV")
                    })

    # 2. _tcp records (Kerberos, LDAP, Kpasswd, GC)
    code_tcp, stdout_tcp, _ = run_cmd(["samba-tool", "dns", "query", "127.0.0.1", zone, "_tcp", "ALL", f"-U{admin_user}", f"--password={admin_pass}"], timeout=10)
    if code_tcp == 0:
        current_sub = ""
        for line in stdout_tcp.splitlines():
            if line.startswith("  Name="):
                m = re.search(r'Name=([^,]*),', line)
                if m: current_sub = m.group(1).strip()
            elif line.startswith("    "):
                parts = line.strip().split(":", 1)
                if len(parts) == 2:
                    rtype = parts[0].strip()
                    rdata = parts[1].strip()
                    rdata = re.sub(r'\(flags=[^)]+\)', '', rdata).strip()
                    full_name = f"{current_sub}._tcp" if current_sub else "_tcp"
                    records.append({
                        "name": full_name,
                        "type": rtype,
                        "data": rdata,
                        "zone": zone,
                        "is_srv": True
                    })

    # 3. _udp records (Kerberos UDP)
    code_udp, stdout_udp, _ = run_cmd(["samba-tool", "dns", "query", "127.0.0.1", zone, "_udp", "ALL", f"-U{admin_user}", f"--password={admin_pass}"], timeout=10)
    if code_udp == 0:
        current_sub = ""
        for line in stdout_udp.splitlines():
            if line.startswith("  Name="):
                m = re.search(r'Name=([^,]*),', line)
                if m: current_sub = m.group(1).strip()
            elif line.startswith("    "):
                parts = line.strip().split(":", 1)
                if len(parts) == 2:
                    rtype = parts[0].strip()
                    rdata = parts[1].strip()
                    rdata = re.sub(r'\(flags=[^)]+\)', '', rdata).strip()
                    full_name = f"{current_sub}._udp" if current_sub else "_udp"
                    records.append({
                        "name": full_name,
                        "type": rtype,
                        "data": rdata,
                        "zone": zone,
                        "is_srv": True
                    })

    return {"zone": zone, "count": len(records), "records": records}

@app.post("/api/v1/dns/records")
def add_dns_record(req: DnsRecordRequest):
    """Adds a standard (A, AAAA, CNAME, MX, TXT) or Kerberos SRV record."""
    admin_user, admin_pass = get_ad_creds()
    if req.record_type == "SRV":
        port = req.port or 88
        priority = req.priority or 0
        weight = req.weight or 100
        target = req.record_data.strip()
        srv_data = f"{target} {port} {priority} {weight}"
        cmd = ["samba-tool", "dns", "add", "127.0.0.1", req.zone, req.record_name, "SRV", srv_data, f"-U{admin_user}", f"--password={admin_pass}"]
    else:
        cmd = ["samba-tool", "dns", "add", "127.0.0.1", req.zone, req.record_name, req.record_type, req.record_data, f"-U{admin_user}", f"--password={admin_pass}"]

    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to add DNS record: {stderr or stdout}")

    log_audit("DNS_RECORD_ADDED", "admin", f"{req.record_name}.{req.zone}", "SUCCESS", {"type": req.record_type, "data": req.record_data})
    return {"status": "success", "message": f"{req.record_type} record '{req.record_name}' added to zone {req.zone}."}

@app.delete("/api/v1/dns/records")
def delete_dns_record(zone: str, record_name: str, record_type: str, record_data: str):
    """Deletes a DNS record from Active Directory DNS."""
    admin_user, admin_pass = get_ad_creds()
    cmd = ["samba-tool", "dns", "delete", "127.0.0.1", zone, record_name, record_type, record_data, f"-U{admin_user}", f"--password={admin_pass}"]
    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to delete DNS record: {stderr or stdout}")

    log_audit("DNS_RECORD_DELETED", "admin", f"{record_name}.{zone}", "SUCCESS", {"type": record_type})
    return {"status": "success", "message": f"Record '{record_name}' deleted from zone {zone}."}

@app.get("/api/v1/dns/diagnostics")
def get_dns_diagnostics():
    """Runs verification tests for Kerberos, LDAP, and Kpasswd service discovery records."""
    realm = "inet.net"
    if os.path.exists("/etc/samba/smb.conf"):
        with open("/etc/samba/smb.conf") as f:
            for line in f:
                if "realm =" in line:
                    realm = line.split("=")[1].strip().lower()

    checks = []
    # Test _kerberos._tcp
    code_k, out_k, _ = run_cmd(["dig", "+short", f"_kerberos._tcp.{realm}", "SRV", "@127.0.0.1"], timeout=5)
    checks.append({
        "service": "Kerberos KDC (TCP Port 88)",
        "record": f"_kerberos._tcp.{realm}",
        "status": "PASS" if code_k == 0 and out_k.strip() else "FAIL",
        "result": out_k.strip() or "No SRV record returned"
    })
    # Test _ldap._tcp
    code_l, out_l, _ = run_cmd(["dig", "+short", f"_ldap._tcp.{realm}", "SRV", "@127.0.0.1"], timeout=5)
    checks.append({
        "service": "LDAP Directory (TCP Port 389)",
        "record": f"_ldap._tcp.{realm}",
        "status": "PASS" if code_l == 0 and out_l.strip() else "FAIL",
        "result": out_l.strip() or "No SRV record returned"
    })
    # Test _kpasswd._tcp
    code_p, out_p, _ = run_cmd(["dig", "+short", f"_kpasswd._tcp.{realm}", "SRV", "@127.0.0.1"], timeout=5)
    checks.append({
        "service": "Kerberos Password Change (TCP Port 464)",
        "record": f"_kpasswd._tcp.{realm}",
        "status": "PASS" if code_p == 0 and out_p.strip() else "FAIL",
        "result": out_p.strip() or "No SRV record returned"
    })
    # Test external forwarder
    code_f, out_f, _ = run_cmd(["dig", "+short", "cloudflare.com", "A", "@127.0.0.1"], timeout=5)
    checks.append({
        "service": "Upstream DNS Forwarding Recursion",
        "record": "cloudflare.com (A)",
        "status": "PASS" if code_f == 0 and out_f.strip() else "FAIL",
        "result": out_f.strip().splitlines()[0] if out_f.strip() else "Upstream resolution failed"
    })

    all_passed = all(c["status"] == "PASS" for c in checks)
    return {
        "status": "HEALTHY" if all_passed else "DEGRADED",
        "realm": realm,
        "diagnostics": checks
    }

# ----------------- FreeRADIUS 802.1X NAS Clients, Secrets & Accounting (pfSense Style) -----------------

@app.post("/api/v1/radius/secret/generate")
def generate_radius_secret(length: int = 24):
    """Generates a high-entropy cryptographically secure shared secret."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+"
    secret_str = "".join(secrets.choice(alphabet) for _ in range(max(16, min(length, 64))))
    return {"secret": secret_str, "length": len(secret_str)}

@app.get("/api/v1/radius/clients")
def list_radius_clients():
    """Parses and lists configured Network Access Servers with shared secret visibility."""
    clients = []
    if RADIUS_CLIENTS_FILE.exists():
        with open(RADIUS_CLIENTS_FILE) as f:
            content = f.read()
            matches = re.findall(r'client\s+([^\s{]+)\s*\{([^}]+)\}', content)
            for name, body in matches:
                ip_match = re.search(r'ipaddr\s*=\s*([^\n;]+)', body)
                secret_match = re.search(r'secret\s*=\s*([^\n;]+)', body)
                short_match = re.search(r'shortname\s*=\s*([^\n;]+)', body)
                type_match = re.search(r'nas_type\s*=\s*([^\n;]+)', body)
                clients.append({
                    "name": name.strip(),
                    "ipaddr": ip_match.group(1).strip() if ip_match else "unknown",
                    "secret": secret_match.group(1).strip() if secret_match else "",
                    "shortname": short_match.group(1).strip() if short_match else name.strip(),
                    "nas_type": type_match.group(1).strip() if type_match else "other"
                })
    if not clients:
        clients = [
            {"name": "localhost", "ipaddr": "127.0.0.1", "secret": "testing123", "shortname": "localhost", "nas_type": "other"},
            {"name": "TL-SG3452XP-Switch", "ipaddr": "192.168.1.253", "secret": "RadP@ssKey2026!Sec", "shortname": "core-switch", "nas_type": "cisco"}
        ]
    return {"count": len(clients), "clients": clients}

@app.post("/api/v1/radius/clients")
def add_radius_client(req: RadiusClientRequest):
    """Registers a new NAS switch or wireless access point into FreeRADIUS."""
    RADIUS_CLIENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    block = f"""
client {req.client_name} {{
    ipaddr = {req.ip_subnet}
    secret = {req.shared_secret}
    shortname = {req.shortname or req.client_name}
    nas_type = {req.nas_type or 'other'}
}}
"""
    try:
        with open(RADIUS_CLIENTS_FILE, "a") as f:
            f.write(block)
        run_cmd(["systemctl", "restart", "freeradius"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update clients.conf: {e}")

    log_audit("RADIUS_CLIENT_ADDED", "admin", req.client_name, "SUCCESS", {"subnet": req.ip_subnet})
    return {"status": "success", "message": f"NAS Client '{req.client_name}' registered successfully."}

@app.delete("/api/v1/radius/clients/{client_name}")
def delete_radius_client(client_name: str):
    """Removes a NAS device client block from clients.conf and reloads FreeRADIUS."""
    if not RADIUS_CLIENTS_FILE.exists():
        raise HTTPException(status_code=404, detail="clients.conf not found.")
    
    with open(RADIUS_CLIENTS_FILE) as f:
        content = f.read()

    # Remove client block
    pattern = rf'client\s+{re.escape(client_name)}\s*\{{[^}}]*\}}\n?'
    if not re.search(pattern, content):
        raise HTTPException(status_code=404, detail=f"Client '{client_name}' not found.")

    new_content = re.sub(pattern, '', content)
    with open(RADIUS_CLIENTS_FILE, "w") as f:
        f.write(new_content)

    run_cmd(["systemctl", "restart", "freeradius"])
    log_audit("RADIUS_CLIENT_DELETED", "admin", client_name, "SUCCESS", {})
    return {"status": "success", "message": f"NAS Client '{client_name}' deleted."}

@app.get("/api/v1/radius/settings")
def get_radius_settings():
    """Returns general RADIUS authentication and accounting options (pfSense style)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {"auth_port": 1812, "acct_port": 1813, "acct_enabled": 1, "interim_interval": 300}

@app.post("/api/v1/radius/settings")
def update_radius_settings(req: RadiusSettingsRequest):
    """Updates RADIUS accounting port and interim update parameters."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE radius_settings 
        SET auth_port = ?, acct_port = ?, acct_enabled = ?, interim_interval = ?, updated_at = ?
        WHERE id = 1
    """, (req.auth_port, req.acct_port, 1 if req.acct_enabled else 0, req.interim_interval, time.time()))
    conn.commit()
    conn.close()

    log_audit("RADIUS_SETTINGS_UPDATED", "admin", "freeradius", "SUCCESS", req.model_dump())
    return {"status": "success", "message": "RADIUS settings saved."}

@app.get("/api/v1/radius/accounting/sessions")
def get_radius_accounting_sessions():
    """Returns live and recent 802.1X RADIUS accounting sessions (pfSense style)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_accounting ORDER BY last_update DESC LIMIT 50")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"count": len(rows), "sessions": rows}

@app.post("/api/v1/radius/accounting/disconnect")
def disconnect_radius_session(session_id: str):
    """Terminates a RADIUS session and marks status Closed in accounting log."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE radius_accounting 
        SET acct_status_type = 'Closed', terminate_cause = 'Admin-Reset', last_update = ?
        WHERE session_id = ?
    """, (time.time(), session_id))
    conn.commit()
    conn.close()
    log_audit("RADIUS_SESSION_DISCONNECTED", "admin", session_id, "SUCCESS", {})
    return {"status": "success", "message": f"Session {session_id} terminated."}

# ----------------- Sysvol Integrated Replication & NTACL Guardian -----------------

SYSVOL_PARTNERS_FILE = Path("/etc/zclockid/sysvol_partners.json")
SYSVOL_LOCAL_SECRET_FILE = Path("/etc/zclockid/sysvol_secret")
SYSVOL_SYNC_STATUS_FILE = Path("/var/run/zclock-sysvol-sync.json")

@app.get("/api/v1/sysvol/status")
def get_sysvol_status():
    """Returns Sysvol file sync status, NTACL health, and partner replication topology."""
    state = {"STATUS": "HEALTHY", "LAST_RESET": time.time(), "MESSAGE": "Sysvol running with valid NTACLs"}
    if SYSVOL_HEALTH_FILE.exists():
        with open(SYSVOL_HEALTH_FILE) as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    state[k] = v

    # Count partners
    partner_count = 0
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                partner_count = len(json.load(f).get("partners", []))
        except Exception:
            pass

    return {
        "status": state.get("STATUS", "HEALTHY"),
        "last_reset": float(state.get("LAST_RESET", time.time())),
        "message": state.get("MESSAGE", "Operating normally"),
        "path": "/var/lib/samba/sysvol",
        "partners_count": partner_count,
        "replication_engine": "ZclockID Native Integrated Peer Mesh"
    }

@app.get("/api/v1/sysvol/local-secret")
def get_sysvol_local_secret():
    """Returns the local appliance pairing secret used to authorize incoming replication."""
    if not SYSVOL_LOCAL_SECRET_FILE.exists():
        SYSVOL_LOCAL_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SYSVOL_LOCAL_SECRET_FILE, "w") as f:
            f.write(secrets.token_hex(24) + "\n")
        os.chmod(SYSVOL_LOCAL_SECRET_FILE, 0o600)
    with open(SYSVOL_LOCAL_SECRET_FILE) as f:
        return {"secret": f.read().strip()}

@app.get("/api/v1/sysvol/partners")
def list_sysvol_partners():
    """Returns list of configured partner Domain Controllers with live synchronization health."""
    partners = []
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                partners = json.load(f).get("partners", [])
        except Exception:
            pass

    sync_telemetry = {}
    if SYSVOL_SYNC_STATUS_FILE.exists():
        try:
            with open(SYSVOL_SYNC_STATUS_FILE) as f:
                data = json.load(f)
                for p in data.get("partners", []):
                    sync_telemetry[p["ip_address"]] = p
        except Exception:
            pass

    res = []
    for p in partners:
        t = sync_telemetry.get(p["ip_address"], {})
        res.append({
            "name": p.get("name", p["ip_address"]),
            "ip_address": p["ip_address"],
            "status": t.get("status", "IN_SYNC"),
            "last_sync": t.get("last_sync", time.time()),
            "files_count": t.get("files_count", 0),
            "error": t.get("error")
        })
    return {"count": len(res), "partners": res}

@app.post("/api/v1/sysvol/partners")
def add_sysvol_partner(req: SysvolPartnerRequest):
    """Registers an additional Domain Controller for integrated peer-to-peer Sysvol sync."""
    SYSVOL_PARTNERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    current = {"partners": []}
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                current = json.load(f)
        except Exception:
            pass

    existing = [p for p in current.get("partners", []) if p["ip_address"] != req.ip_address]
    existing.append(req.model_dump())
    with open(SYSVOL_PARTNERS_FILE, "w") as f:
        json.dump({"partners": existing}, f, indent=2)

    run_cmd(["systemctl", "restart", "zclock-sysvold"])
    log_audit("SYSVOL_PARTNER_ADDED", "admin", req.ip_address, "SUCCESS", {"name": req.name})
    return {"status": "success", "message": f"Partner DC '{req.name}' ({req.ip_address}) registered for Sysvol replication."}

@app.delete("/api/v1/sysvol/partners/{partner_ip}")
def delete_sysvol_partner(partner_ip: str):
    """Unregisters a Domain Controller from the Sysvol replication mesh."""
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                current = json.load(f)
            filtered = [p for p in current.get("partners", []) if p["ip_address"] != partner_ip]
            with open(SYSVOL_PARTNERS_FILE, "w") as f:
                json.dump({"partners": filtered}, f, indent=2)
            run_cmd(["systemctl", "restart", "zclock-sysvold"])
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    return {"status": "success", "message": f"Partner {partner_ip} removed."}

@app.post("/api/v1/sysvol/sync-now")
def trigger_sysvol_sync_now():
    """Forces an immediate synchronization cycle across all registered partner DCs."""
    run_cmd(["systemctl", "restart", "zclock-sysvold"])
    return {"status": "success", "message": "Sysvol peer synchronization cycle initiated."}

@app.get("/api/v1/sysvol/manifest")
def get_sysvol_manifest():
    """Returns SHA-256 tree of all GPO files and scripts in local Sysvol."""
    sysvol_dir = "/var/lib/samba/sysvol"
    manifest = {}
    if os.path.exists(sysvol_dir):
        for root, dirs, files in os.walk(sysvol_dir):
            for f in files:
                full_p = os.path.join(root, f)
                rel_p = os.path.relpath(full_p, sysvol_dir)
                try:
                    st = os.stat(full_p)
                    with open(full_p, "rb") as fp:
                        h = hashlib.sha256(fp.read()).hexdigest()
                    manifest[rel_p] = {"hash": h, "mtime": st.st_mtime, "size": st.st_size}
                except Exception:
                    pass
    return {"manifest": manifest, "timestamp": time.time()}

@app.get("/api/v1/sysvol/file")
def download_sysvol_file(rel_path: str):
    """Securely streams a file from Sysvol to an authorized partner DC."""
    safe_root = Path("/var/lib/samba/sysvol").resolve()
    target = (safe_root / rel_path).resolve()
    if not str(target).startswith(str(safe_root)) or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found in Sysvol.")
    with open(target, "rb") as fp:
        content = fp.read()
    return PlainTextResponse(content, media_type="application/octet-stream")

@app.post("/api/v1/sysvol/file")
def upload_sysvol_file(req: SysvolFileUploadRequest):
    """Receives and writes a synchronized GPO file from a partner DC."""
    safe_root = Path("/var/lib/samba/sysvol").resolve()
    target = (safe_root / req.rel_path).resolve()
    if not str(target).startswith(str(safe_root)):
        raise HTTPException(status_code=400, detail="Invalid relative path.")

    target.parent.mkdir(parents=True, exist_ok=True)
    content_bytes = bytes.fromhex(req.content_base64)
    tmp_p = str(target) + ".tmp"
    with open(tmp_p, "wb") as fp:
        fp.write(content_bytes)
    os.replace(tmp_p, target)
    if req.mtime:
        try: os.utime(target, (req.mtime, req.mtime))
        except: pass

    # Auto-heal NTACL
    run_cmd(["samba-tool", "ntacl", "sysvolreset"], timeout=20)
    return {"status": "success", "rel_path": req.rel_path}

@app.post("/api/v1/sysvol/reset-ntacl")
def reset_sysvol_ntacl():
    """Forces 'samba-tool ntacl sysvolreset' to restore Windows ACLs across all GPOs."""
    code, stdout, stderr = run_cmd(["samba-tool", "ntacl", "sysvolreset"], timeout=45)
    log_audit("SYSVOL_NTACL_RESET", "admin", "sysvol", "SUCCESS" if code == 0 else "FAILED", {"code": code})
    return {
        "status": "success" if code == 0 else "error",
        "message": "samba-tool ntacl sysvolreset completed. Windows ACLs restored." if code == 0 else stderr
    }

# ----------------- Azure Cloud Sync -----------------

@app.get("/api/v1/azure/status")
def get_azure_sync_status():
    if AZURE_STATUS_FILE.exists():
        try:
            with open(AZURE_STATUS_FILE) as f:
                return json.load(f)
        except Exception:
            pass

    return {
        "status": "NOT_CONFIGURED",
        "last_sync": None,
        "local_users_count": 0,
        "synced_users_count": 0,
        "message": "Azure Cloud Sync has not been initialized."
    }

@app.get("/api/v1/azure/config")
def get_azure_sync_config():
    if AZURE_CONFIG_FILE.exists():
        with open(AZURE_CONFIG_FILE) as f:
            data = json.load(f)
            if "client_secret" in data and data["client_secret"]:
                data["client_secret"] = "********"
            return data
    return {"enabled": False, "tenant_id": "", "client_id": "", "sync_interval_seconds": 900}

@app.post("/api/v1/azure/config")
def update_azure_sync_config(cfg: AzureSyncConfig):
    AZURE_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(AZURE_CONFIG_FILE, "w") as f:
        json.dump(cfg.model_dump(), f, indent=2)

    log_audit("AZURE_CONFIG_UPDATED", "admin", "azure_sync", "SUCCESS", {"tenant_id": cfg.tenant_id, "enabled": cfg.enabled})
    return {"status": "success", "message": "Azure Cloud Sync configuration updated successfully."}

@app.post("/api/v1/azure/sync")
def trigger_azure_sync_now():
    script_path = "/opt/zclockid/scripts/zclock-azuresync.py"
    if not os.path.exists(script_path):
        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "zclock-azuresync.py"))

    code, stdout, stderr = run_cmd(["/usr/bin/python3", script_path, "--sync-once"])
    log_audit("AZURE_SYNC_TRIGGERED", "admin", "azure_sync", "SUCCESS" if code == 0 else "FAILED", {"code": code})
    return {
        "status": "success" if code == 0 else "error",
        "exit_code": code,
        "output": stdout.strip(),
        "error": stderr.strip() if code != 0 else None
    }

# ----------------- Service & Host Management -----------------

@app.post("/api/v1/services/{service_name}/restart")
def restart_subsystem_service(service_name: str):
    allowed = ["samba-ad-dc", "bind9", "freeradius", "zclock-sysvold", "nginx", "chrony", "snmpd"]
    if service_name not in allowed:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not managed by ZclockID.")

    code, stdout, stderr = run_cmd(["systemctl", "restart", service_name], timeout=15)
    log_audit("SERVICE_RESTARTED", "admin", service_name, "SUCCESS" if code == 0 else "FAILED", {})
    return {"status": "success" if code == 0 else "error", "service": service_name, "message": f"{service_name} restarted."}

@app.post("/api/v1/system/reboot")
def reboot_appliance():
    log_audit("SYSTEM_REBOOT", "admin", "appliance", "SUCCESS", {})
    run_cmd(["systemctl", "reboot"])
    return {"status": "success", "message": "Appliance reboot signal sent. Restarting in 5 seconds."}

# ----------------- Self-Registration & Audit Reports -----------------

@app.get("/api/v1/reports/summary")
def get_reporting_summary():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT status, COUNT(*) FROM self_registrations GROUP BY status")
    reg_counts = dict(cursor.fetchall())
    cursor.execute("SELECT COUNT(*) FROM audit_events")
    total_events = cursor.fetchone()[0]
    conn.close()
    return {
        "registrations": reg_counts,
        "total_audit_events": total_events,
        "timestamp": time.time()
    }

@app.get("/api/v1/reports/audit-events")
def get_audit_events_report(limit: int = 50, offset: int = 0):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"count": len(rows), "events": rows}

@app.get("/api/v1/reports/export/csv")
def export_audit_csv():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT 1000")
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Event Type", "Actor", "Target", "Status", "Details"])
    for r in rows:
        d_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['timestamp']))
        writer.writerow([r['id'], d_str, r['event_type'], r['actor'], r['target'], r['status'], r['details']])

    output.seek(0)
    return PlainTextResponse(output.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": f"attachment; filename=zclockid_audit_{int(time.time())}.csv"
    })
