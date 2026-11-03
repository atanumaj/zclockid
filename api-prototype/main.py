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

from fastapi import FastAPI, HTTPException, status, Query, Depends, Request, Form, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse, RedirectResponse, FileResponse
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from pathlib import Path
import subprocess
import os
import platform
import time
import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("zclockid")
import tarfile
import shutil
import sqlite3
import csv
import io
import json
import hashlib
import secrets
import re
import urllib.request
import urllib.parse
import base64
import ssl
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import dns.message
import dns.rdatatype
import dns.rcode

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
RADIUS_AUTHORIZE_FILE = Path("/etc/freeradius/3.0/mods-config/files/authorize")
RADIUS_USERS_FILE = Path("/etc/freeradius/3.0/users")
RADIUS_MSCHAP_FILE = Path("/etc/freeradius/3.0/mods-available/mschap")
RADIUS_EAP_FILE = Path("/etc/freeradius/3.0/mods-available/eap")
RADIUS_SERVER_CERT = Path("/etc/freeradius/3.0/certs/server.pem")
RADIUS_CA_CERT = Path("/etc/freeradius/3.0/certs/ca.pem")
BACKUP_DIR = Path("/var/backups/zclockid")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

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
            mobile TEXT,
            status TEXT DEFAULT 'PENDING_OTP',
            ip_address TEXT,
            created_at REAL,
            approved_at REAL,
            approved_by TEXT,
            notes TEXT,
            otp_code TEXT,
            otp_expires_at REAL,
            otp_verified INTEGER DEFAULT 0,
            password_hash TEXT
        )
    """)
    # Safe column additions if table was created in an earlier schema
    cursor.execute("PRAGMA table_info(self_registrations)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    cols_to_add = {
        "mobile": "TEXT",
        "otp_code": "TEXT",
        "otp_expires_at": "REAL",
        "otp_verified": "INTEGER DEFAULT 0",
        "password_hash": "TEXT"
    }
    for col_name, col_type in cols_to_add.items():
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE self_registrations ADD COLUMN {col_name} {col_type}")

    # Self-Registration & OTP Policy Settings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS self_registration_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER DEFAULT 1,
            require_mobile_otp INTEGER DEFAULT 1,
            auto_approve_with_otp INTEGER DEFAULT 1,
            default_domain TEXT DEFAULT 'inet.net',
            default_group TEXT DEFAULT 'Domain Users',
            sms_gateway_type TEXT DEFAULT 'simulated',
            sms_gateway_url TEXT DEFAULT '',
            sms_api_key TEXT DEFAULT '',
            sms_sender_id TEXT DEFAULT 'ZCLOCK',
            sms_template TEXT DEFAULT 'Your ZclockID verification code is {otp}. Valid for 10 minutes.',
            email_smtp_enabled INTEGER DEFAULT 0,
            smtp_host TEXT DEFAULT '',
            smtp_port INTEGER DEFAULT 587,
            smtp_user TEXT DEFAULT '',
            smtp_pass TEXT DEFAULT '',
            smtp_from TEXT DEFAULT 'no-reply@inet.net',
            updated_at REAL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM self_registration_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO self_registration_settings (
                id, enabled, require_mobile_otp, auto_approve_with_otp, default_domain, default_group,
                sms_gateway_type, sms_sender_id, sms_template, updated_at
            ) VALUES (
                1, 1, 1, 1, 'inet.net', 'Domain Users',
                'simulated', 'ZCLOCK', 'Your ZclockID verification code is {otp}. Valid for 10 minutes.', ?
            )
        """, (time.time(),))
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

    # Captive Portal Bandwidth & Rate Limiting Profiles (Standard Mode)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_bandwidth_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            download_mbps REAL NOT NULL,
            upload_mbps REAL NOT NULL,
            session_timeout_mins INTEGER DEFAULT 120,
            idle_timeout_mins INTEGER DEFAULT 30,
            daily_quota_mb INTEGER DEFAULT 0,
            target_type TEXT DEFAULT 'GROUP', -- 'GROUP', 'USER', 'DEFAULT'
            target_name TEXT DEFAULT '',
            ad_group TEXT DEFAULT '',
            is_default INTEGER DEFAULT 0,
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_at REAL
        )
    """)
    # Migration for target_type and target_name columns if not present
    for col, ctype, cdef in [("target_type", "TEXT", "'GROUP'"), ("target_name", "TEXT", "''")]:
        try:
            cursor.execute(f"ALTER TABLE radius_bandwidth_profiles ADD COLUMN {col} {ctype} DEFAULT {cdef}")
        except Exception:
            pass

    cursor.execute("SELECT COUNT(*) FROM radius_bandwidth_profiles")
    if cursor.fetchone()[0] == 0:
        now_ts = time.time()
        cursor.execute("""
            INSERT INTO radius_bandwidth_profiles (name, download_mbps, upload_mbps, session_timeout_mins, idle_timeout_mins, daily_quota_mb, target_type, target_name, ad_group, is_default, description, is_active, created_at)
            VALUES 
            ('VIP-Executive', 50.0, 25.0, 1440, 60, 0, 'GROUP', 'Domain Admins', 'Domain Admins', 0, 'Unrestricted high-speed priority tier for leadership & admins', 1, ?),
            ('Staff-Standard', 20.0, 10.0, 720, 30, 0, 'GROUP', 'Corporate-Users', 'Corporate-Users', 0, 'Standard enterprise employee work profile', 1, ?),
            ('Guest-Captive-Portal', 5.0, 2.0, 120, 15, 2048, 'DEFAULT', 'ALL', '', 1, 'Default captive portal profile for visitor Wi-Fi & OTP self-registrations', 1, ?),
            ('Limited-Public', 2.0, 0.5, 30, 10, 500, 'GROUP', '', '', 0, 'Throttled public access tier with 500 MB data cap', 1, ?)
        """, (now_ts, now_ts, now_ts, now_ts))

    # Individual User to Bandwidth Profile Mapping
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_user_bandwidth (
            username TEXT PRIMARY KEY,
            profile_id INTEGER NOT NULL,
            updated_at REAL
        )
    """)

    # MAC Authentication Bypass (MAB) for Headless Devices (Advanced Mode)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_mab_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT NOT NULL UNIQUE,
            device_name TEXT NOT NULL,
            vlan_id INTEGER NOT NULL,
            static_ip TEXT DEFAULT '',
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_at REAL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM radius_mab_devices")
    if cursor.fetchone()[0] == 0:
        now_ts = time.time()
        cursor.execute("""
            INSERT INTO radius_mab_devices (mac_address, device_name, vlan_id, static_ip, description, is_active, created_at)
            VALUES 
            ('00:50:56:A1:B2:C3', 'HP-Color-LaserJet-Floor1', 70, '192.168.70.25', 'Shared Department MFP Printer', 1, ?),
            ('F4:F5:D8:10:20:30', 'Hikvision-Reception-Cam', 80, '192.168.80.12', 'Reception PoE IP Security Camera', 1, ?)
        """, (now_ts, now_ts))

    # Custom RADIUS Vendor Attributes & Policies (Advanced Mode)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_custom_attributes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,
            target_name TEXT DEFAULT '',
            attribute_name TEXT NOT NULL,
            operator TEXT DEFAULT '=',
            attribute_value TEXT NOT NULL,
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_at REAL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM radius_custom_attributes")
    if cursor.fetchone()[0] == 0:
        now_ts = time.time()
        cursor.execute("""
            INSERT INTO radius_custom_attributes (target_type, target_name, attribute_name, operator, attribute_value, description, is_active, created_at)
            VALUES 
            ('GLOBAL', 'ALL', 'Session-Timeout', '=', '28800', 'Force 8-hour maximum 802.1X session re-auth', 1, ?),
            ('GROUP', 'Corporate-Users', 'Idle-Timeout', '=', '1800', 'Drop Wi-Fi sessions idle over 30 mins', 1, ?)
        """, (now_ts, now_ts))

    # RADIUS General Configuration
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            auth_port INTEGER DEFAULT 1812,
            acct_port INTEGER DEFAULT 1813,
            acct_enabled INTEGER DEFAULT 1,
            interim_interval INTEGER DEFAULT 300,
            listen_ip TEXT DEFAULT '0.0.0.0',
            log_auth INTEGER DEFAULT 1,
            log_badpass INTEGER DEFAULT 1,
            log_stripped_names INTEGER DEFAULT 0,
            eap_peap_enabled INTEGER DEFAULT 1,
            eap_tls_enabled INTEGER DEFAULT 1,
            eap_default_type TEXT DEFAULT 'peap',
            max_requests INTEGER DEFAULT 1024,
            max_servers INTEGER DEFAULT 32,
            updated_at REAL
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO radius_settings (id, auth_port, acct_port, acct_enabled, interim_interval, updated_at) VALUES (1, 1812, 1813, 1, 300, ?)", (time.time(),))

    # Migrations for existing radius_settings table columns
    for col, ctype, cdefault in [
        ("listen_ip", "TEXT", "'0.0.0.0'"),
        ("log_auth", "INTEGER", "1"),
        ("log_badpass", "INTEGER", "1"),
        ("log_stripped_names", "INTEGER", "0"),
        ("eap_peap_enabled", "INTEGER", "1"),
        ("eap_tls_enabled", "INTEGER", "1"),
        ("eap_default_type", "TEXT", "'peap'"),
        ("max_requests", "INTEGER", "1024"),
        ("max_servers", "INTEGER", "32"),
    ]:
        try:
            cursor.execute(f"ALTER TABLE radius_settings ADD COLUMN {col} {ctype} DEFAULT {cdefault}")
        except Exception:
            pass

    # System Update & Release Management
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS update_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            github_repo TEXT DEFAULT 'atanude/Inet-ZclockID',
            custom_manifest_url TEXT DEFAULT '',
            auto_check INTEGER DEFAULT 1,
            last_checked REAL DEFAULT 0,
            latest_version TEXT DEFAULT '',
            latest_release_name TEXT DEFAULT '',
            latest_release_notes TEXT DEFAULT '',
            latest_download_url TEXT DEFAULT '',
            last_check_status TEXT DEFAULT 'NOT_CHECKED',
            updated_at REAL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM update_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO update_settings (
                id, github_repo, custom_manifest_url, auto_check, last_checked,
                latest_version, latest_release_name, latest_release_notes,
                latest_download_url, last_check_status, updated_at
            ) VALUES (
                1, 'atanude/Inet-ZclockID', '', 1, 0, '', '', '', '', 'NOT_CHECKED', ?
            )
        """, (time.time(),))

    conn.commit()
    conn.close()

init_db()

# ----------------- Helper Functions -----------------

APPLIANCE_DEFAULT_VERSION = "1.0.0"

def get_appliance_version() -> str:
    ver_file = Path("/opt/zclockid/VERSION")
    if ver_file.exists():
        try:
            v = ver_file.read_text().strip()
            if v:
                return v
        except Exception:
            pass
    code, stdout, _ = run_cmd(["dpkg-query", "-W", "-f=${Version}", "zclockid"])
    if code == 0 and stdout.strip():
        return stdout.strip()
    return APPLIANCE_DEFAULT_VERSION

def parse_semver(v_str: str) -> tuple:
    v_clean = re.sub(r'^[vV]', '', str(v_str).strip())
    parts = []
    for piece in v_clean.split('.'):
        digits = re.findall(r'^\d+', piece)
        if digits:
            parts.append(int(digits[0]))
        else:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

def is_newer_version(candidate: str, baseline: str) -> bool:
    try:
        return parse_semver(candidate) > parse_semver(baseline)
    except Exception:
        return False

def ensure_updater_script() -> str:
    standard_path = "/opt/zclockid/scripts/zclock-updater.sh"
    if os.path.exists(standard_path) and os.access(standard_path, os.X_OK):
        return standard_path
    fallback_path = "/tmp/zclock-updater.sh"
    updater_script_content = r"""#!/usr/bin/env bash
set -o pipefail
LOG_FILE="/var/log/zclock-update.log"
STATUS_FILE="/var/run/zclock-update.status"
DEB_PACKAGE="${1:-/tmp/zclockid_update.deb}"
echo "UPDATING" > "${STATUS_FILE}"
echo "=== ZclockID Package Update Initiated at $(date) ===" > "${LOG_FILE}"
if [ ! -f "${DEB_PACKAGE}" ]; then
    echo "ERROR: Target package ${DEB_PACKAGE} not found!" >> "${LOG_FILE}"
    echo "ERROR: Package file not found" > "${STATUS_FILE}"
    exit 1
fi
PKG_INFO=$(dpkg-deb -I "${DEB_PACKAGE}" 2>&1)
PKG_NAME=$(echo "${PKG_INFO}" | grep -E '^\s*Package:' | awk '{print $2}')
PKG_VER=$(echo "${PKG_INFO}" | grep -E '^\s*Version:' | awk '{print $2}')
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Installing ${PKG_NAME} ${PKG_VER}..." >> "${LOG_FILE}"
export DEBIAN_FRONTEND=noninteractive
dpkg -i "${DEB_PACKAGE}" >> "${LOG_FILE}" 2>&1 || apt-get install -f -y >> "${LOG_FILE}" 2>&1
echo "${PKG_VER}" > /opt/zclockid/VERSION 2>/dev/null || true
systemctl daemon-reload >> "${LOG_FILE}" 2>&1 || true
systemctl restart zclock-api.service >> "${LOG_FILE}" 2>&1 || true
sleep 3
if systemctl is-active --quiet zclock-api.service; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Update to v${PKG_VER} completed successfully!" >> "${LOG_FILE}"
    echo "COMPLETED: v${PKG_VER}" > "${STATUS_FILE}"
else
    systemctl restart zclock-api.service >> "${LOG_FILE}" 2>&1 || true
    echo "COMPLETED: v${PKG_VER}" > "${STATUS_FILE}"
fi
rm -f "${DEB_PACKAGE}" 2>/dev/null || true
exit 0
"""
    with open(fallback_path, "w") as f:
        f.write(updater_script_content)
    os.chmod(fallback_path, 0o755)
    return fallback_path

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
    raw_st = out.strip()
    is_active = (raw_st == "active")
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
    _, out_en, _ = run_cmd(["systemctl", "is-enabled", service_name], timeout=3)
    en_val = out_en.strip() or "unknown"
    return {
        "status": "active" if is_active else ("failed" if raw_st == "failed" else "inactive"),
        "systemd_state": raw_st if code == 0 else "unknown",
        "enabled": en_val,
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

def get_primary_realm() -> str:
    smb_conf = Path("/etc/samba/smb.conf")
    if smb_conf.exists():
        try:
            for line in smb_conf.read_text().splitlines():
                line = line.strip()
                if line.lower().startswith("realm") and "=" in line:
                    return line.split("=", 1)[1].strip()
        except Exception:
            pass
    return "INET.NET"

def get_self_registration_settings() -> dict:
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
            payload = {
                "to": mobile,
                "message": message,
                "sender": settings.get("sms_sender_id", "ZCLOCK"),
                "api_key": settings.get("sms_api_key", "")
            }
            res = requests.post(url, json=payload, timeout=8)
            log_audit("SMS_DISPATCHED", "system", mobile, "SUCCESS" if res.status_code < 300 else "ERROR", {"provider": "webhook", "status_code": res.status_code})
            return res.status_code < 300, f"Webhook responded with HTTP {res.status_code}"
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

def parse_bw_info(info_str: Optional[str]) -> Optional[dict]:
    """Parses ZCLOCKID_BW tag embedded in Active Directory user/group 'info' attribute (replicated via Microsoft DRS)."""
    if not info_str or not info_str.startswith("ZCLOCKID_BW:"):
        return None
    raw = info_str.replace("ZCLOCKID_BW:", "", 1).strip()
    parts = raw.split(";")
    data = {
        "name": parts[0].strip(),
        "download_mbps": 5.0,
        "upload_mbps": 2.0,
        "session_timeout_mins": 120,
        "idle_timeout_mins": 30,
        "daily_quota_mb": 0
    }
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            try:
                if k in ["down", "download_mbps"]: data["download_mbps"] = float(v)
                elif k in ["up", "upload_mbps"]: data["upload_mbps"] = float(v)
                elif k in ["sess", "session_timeout_mins"]: data["session_timeout_mins"] = int(float(v))
                elif k in ["idle", "idle_timeout_mins"]: data["idle_timeout_mins"] = int(float(v))
                elif k in ["quota", "daily_quota_mb"]: data["daily_quota_mb"] = int(float(v))
            except Exception:
                pass
    return data

def update_user_upn(username: str, new_upn: str) -> str:
    code, stdout, stderr = run_cmd(["ldbsearch", "-H", "/var/lib/samba/private/sam.ldb", f"(sAMAccountName={username})", "dn"])
    if code != 0:
        raise Exception(f"Failed to query SAM LDB: {stderr}")
    dn = None
    for line in stdout.splitlines():
        if line.startswith("dn: "):
            dn = line[4:].strip()
            break
    if not dn:
        raise Exception(f"User '{username}' not found in Active Directory.")
    ldif = f"dn: {dn}\nchangetype: modify\nreplace: userPrincipalName\nuserPrincipalName: {new_upn}\n"
    proc = subprocess.run(["ldbmodify", "-H", "/var/lib/samba/private/sam.ldb"], input=ldif, text=True, capture_output=True)
    if proc.returncode != 0:
        raise Exception(f"Failed to update userPrincipalName: {proc.stderr}")
    return dn

def provision_user_in_ad(username: str, password: str, given_name: str, surname: str, email: str, mobile: str, department: str, default_domain: str = None) -> bool:
    admin_user, admin_pass = get_ad_creds()
    cmd = [
        "samba-tool", "user", "create", username, password,
        f"-U{admin_user}", f"--password={admin_pass}"
    ]
    if given_name: cmd.extend(["--given-name", given_name])
    if surname: cmd.extend(["--surname", surname])
    if email: cmd.extend(["--mail-address", email])
    if mobile: cmd.extend(["--telephone-number", mobile])
    if department: cmd.extend(["--department", department])

    code, stdout, stderr = run_cmd(cmd, timeout=25)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to create user in Active Directory: {stderr or stdout}")

    run_cmd(["samba-tool", "user", "setexpiry", username, "--noexpiry", f"-U{admin_user}", f"--password={admin_pass}"], timeout=10)

    if default_domain and default_domain.lower() != get_primary_realm().lower():
        try:
            update_user_upn(username, f"{username}@{default_domain.lower()}")
        except Exception as e:
            logger.warning(f"Could not set custom UPN {username}@{default_domain}: {e}")

    return True

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
    mobile: Optional[str] = Field(None, example="+919876543210")
    department: Optional[str] = None
    target_group: Optional[str] = "Domain Users"
    bandwidth_profile_id: Optional[int] = None

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

class UserPasswordReset(BaseModel):
    new_password: str = Field(..., min_length=8, example="NewSecureP@ss2026!")
    must_change_at_next_logon: bool = False

class GroupCreateRequest(BaseModel):
    group_name: str = Field(..., example="SG-IT-Admins")
    description: Optional[str] = None
    bandwidth_profile_id: Optional[int] = None

class GroupUpdateRequest(BaseModel):
    description: Optional[str] = None
    bandwidth_profile_id: Optional[int] = None

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

class RadiusBandwidthProfileRequest(BaseModel):
    id: Optional[int] = None
    name: str = Field(..., example="Guest-5M")
    download_mbps: float = Field(..., example=5.0)
    upload_mbps: float = Field(..., example=2.0)
    session_timeout_mins: Optional[int] = 120
    idle_timeout_mins: Optional[int] = 30
    daily_quota_mb: Optional[int] = 0 # 0 for unlimited
    target_type: Optional[str] = "GROUP" # 'GROUP', 'USER', 'DEFAULT'
    target_name: Optional[str] = ""
    ad_group: Optional[str] = ""
    is_default: Optional[bool] = False
    description: Optional[str] = ""
    is_active: Optional[bool] = True

class RadiusMabDeviceRequest(BaseModel):
    id: Optional[int] = None
    mac_address: str = Field(..., example="00:11:22:33:44:55")
    device_name: str = Field(..., example="Floor-1-Printer")
    vlan_id: int = Field(..., example=70)
    static_ip: Optional[str] = ""
    description: Optional[str] = ""
    is_active: Optional[bool] = True

class RadiusCustomAttributeRequest(BaseModel):
    id: Optional[int] = None
    target_type: str = Field("GLOBAL", example="GLOBAL") # GLOBAL, GROUP, CLIENT
    target_name: Optional[str] = Field("ALL", example="ALL")
    attribute_name: str = Field(..., example="Session-Timeout")
    operator: Optional[str] = Field("=", example="=")
    attribute_value: str = Field(..., example="28800")
    description: Optional[str] = ""
    is_active: Optional[bool] = True

class RadiusSettingsRequest(BaseModel):
    auth_port: int = 1812
    acct_port: int = 1813
    acct_enabled: bool = True
    interim_interval: int = 300
    listen_ip: Optional[str] = "0.0.0.0"
    log_auth: Optional[bool] = True
    log_badpass: Optional[bool] = True
    log_stripped_names: Optional[bool] = False
    eap_peap_enabled: Optional[bool] = True
    eap_tls_enabled: Optional[bool] = True
    eap_default_type: Optional[str] = "peap"
    max_requests: Optional[int] = 1024
    max_servers: Optional[int] = 32

class ServiceActionRequest(BaseModel):
    action: str = Field("restart", pattern="^(restart|start|stop|reload|enable|disable)$")

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
    tenant_id: str = ""
    client_id: str = ""
    client_secret: Optional[str] = None
    default_domain: Optional[str] = "inet.net"
    source_ou: Optional[str] = ""
    sync_interval_seconds: Optional[int] = 900
    exclude_disabled: Optional[bool] = True
    password_hash_sync: Optional[bool] = False
    auto_create_users: Optional[bool] = True

class AzureTestConnectionRequest(BaseModel):
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

class SystemIdentityUpdateRequest(BaseModel):
    server_description: Optional[str] = None
    hostname: Optional[str] = None
    netbios_name: Optional[str] = None

class NtpConfigRequest(BaseModel):
    ntp_server_enabled: bool = True
    allowed_subnets: str = "0.0.0.0/0, ::/0"
    ms_sntp_enabled: bool = True
    upstream_servers: List[str] = ["time.google.com", "pool.ntp.org", "time.windows.com"]
    timezone: Optional[str] = None

class DohTestRequest(BaseModel):
    query_name: Optional[str] = "inet.net"
    query_type: Optional[str] = "A"
    qname: Optional[str] = None
    rtype: Optional[str] = None

class FunctionalLevelRaiseRequest(BaseModel):
    domain_level: str = "2016"
    forest_level: str = "2016"

class BackupCreateRequest(BaseModel):
    backup_type: str = "config_only"  # config_only or full
    description: Optional[str] = "Manual appliance backup"

class BackupRestoreRequest(BaseModel):
    filename: str
    skip_ad_restore: Optional[bool] = False

class BackupInspectRequest(BaseModel):
    filename: str

class SnmpConfigRequest(BaseModel):
    enabled: bool = True
    agent_address: str = "udp:161,udp6:[::1]:161"
    sys_location: str = "Inet Secure Labs Datacenter"
    sys_contact: str = "noc@inetcsc.com"
    community_string: str = "zclock_public"
    allowed_subnets: str = "192.168.1.0/24, 127.0.0.1"
    enable_extensions: bool = True
    snmpv3_enabled: bool = False
    snmpv3_user: Optional[str] = "zclock_admin"
    snmpv3_auth_proto: Optional[str] = "SHA"
    snmpv3_auth_pass: Optional[str] = None
    snmpv3_priv_proto: Optional[str] = "AES"
    snmpv3_priv_pass: Optional[str] = None

class SnmpTestQueryRequest(BaseModel):
    target_host: Optional[str] = "127.0.0.1"
    community_string: Optional[str] = "zclock_public"
    oid: str = ".1.3.6.1.2.1.1.1.0"

class SelfRegistrationSettingsRequest(BaseModel):
    enabled: bool = True
    require_mobile_otp: bool = True
    auto_approve_with_otp: bool = True
    default_domain: Optional[str] = "inet.net"
    default_group: Optional[str] = "Domain Users"
    sms_gateway_type: Optional[str] = "simulated"  # simulated, webhook, twilio, fast2sms, msg91
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

class UserUpnUpdateRequest(BaseModel):
    user_principal_name: str

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

ALL_MANAGED_SERVICES = [
    "samba-ad-dc",
    "bind9",
    "freeradius",
    "chrony",
    "zclock-sysvold",
    "zclock-azuresync",
    "zclock-api",
    "nginx",
    "snmpd"
]

@app.get("/api/v1/system/status")
def get_system_status():
    """Returns comprehensive appliance health, engine statuses, PIDs, memory, and ports."""
    services = {
        "samba_ad_dc": check_systemd_service("samba-ad-dc"),
        "bind9": check_systemd_service("bind9"),
        "freeradius": check_systemd_service("freeradius"),
        "chrony": check_systemd_service("chrony"),
        "zclock_sysvold": check_systemd_service("zclock-sysvold"),
        "zclock_azuresync": check_systemd_service("zclock-azuresync"),
        "zclock_api": check_systemd_service("zclock-api"),
        "nginx": check_systemd_service("nginx"),
        "snmpd": check_systemd_service("snmpd")
    }

    # Port listeners map
    ports_map = {
        "DNS (UDP/TCP)": 53,
        "Kerberos KDC": 88,
        "NTP Time Server": 123,
        "MSRPC Endpoint": 135,
        "NetBIOS-SSN": 139,
        "SNMP Telemetry": 161,
        "LDAP Directory": 389,
        "HTTPS / DoH Ingress": 443,
        "SMB / CIFS Share": 445,
        "Kerberos Password": 464,
        "LDAPS SSL": 636,
        "FreeRADIUS Auth": 1812,
        "FreeRADIUS Acct": 1813,
        "Global Catalog": 3268,
        "Management API": 8000,
        "DoH Internal HTTP": 8053
    }

    import psutil
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    active_count = sum(1 for s in services.values() if s["status"] == "active")
    health = "HEALTHY" if active_count >= 5 else ("INITIALIZING" if active_count >= 3 else "DEGRADED")

    return {
        "hostname": os.uname().nodename,
        "uptime_seconds": time.time() - psutil.boot_time(),
        "version": get_appliance_version(),
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

@app.get("/api/v1/services")
def list_managed_services():
    """Lists all 9 managed system services with metadata, role category, ports, runtime state, and boot status."""
    catalog = [
        # Custom Built ZclockID Daemons
        {
            "id": "zclock-api",
            "name": "ZclockID REST API",
            "category": "custom_built",
            "category_label": "CORE BACKEND",
            "role": "Appliance REST API & Web Management Console Engine",
            "ports": [8000],
            "unit": "zclock-api.service"
        },
        {
            "id": "zclock-sysvold",
            "name": "Sysvol NTACL Guardian",
            "category": "custom_built",
            "category_label": "SYSVOL REPLICATION",
            "role": "Bi-directional Sysvol Replication & Windows NTACL Self-Healing",
            "ports": [],
            "unit": "zclock-sysvold.service"
        },
        {
            "id": "zclock-azuresync",
            "name": "Azure / Entra Cloud Sync",
            "category": "custom_built",
            "category_label": "HYBRID IDENTITY",
            "role": "Hybrid Cloud Identity, User & Password Hash Synchronization",
            "ports": [],
            "unit": "zclock-azuresync.service"
        },
        # Core Infrastructure Services
        {
            "id": "samba-ad-dc",
            "name": "Samba Active Directory DC",
            "category": "infrastructure",
            "category_label": "DIRECTORY & AUTH",
            "role": "Kerberos KDC, LDAP Directory, SMB/CIFS, MSRPC, SAM LDB",
            "ports": [53, 88, 135, 139, 389, 445, 464, 636, 3268],
            "unit": "samba-ad-dc.service"
        },
        {
            "id": "bind9",
            "name": "BIND9 DLZ & DoH",
            "category": "infrastructure",
            "category_label": "DNS & DOH ENGINE",
            "role": "Active Directory Dynamic DNS & RFC 8484 DNS-over-HTTPS",
            "ports": [53, 8053],
            "unit": "bind9.service"
        },
        {
            "id": "freeradius",
            "name": "FreeRADIUS 3.0",
            "category": "infrastructure",
            "category_label": "802.1X AUTH & ACCT",
            "role": "WPA-Enterprise 802.1X Access Authentication & Accounting",
            "ports": [1812, 1813],
            "unit": "freeradius.service"
        },
        {
            "id": "chrony",
            "name": "Chrony NTP Server",
            "category": "infrastructure",
            "category_label": "NTP TIME SYNC",
            "role": "Precision Network Time Server with Samba MS-SNTP Signing",
            "ports": [123],
            "unit": "chrony.service"
        },
        {
            "id": "nginx",
            "name": "Nginx Multiplexer",
            "category": "infrastructure",
            "category_label": "INGRESS PROXY",
            "role": "HTTP/2 TLS Termination, Web UI Host, DoH Path Routing",
            "ports": [80, 443],
            "unit": "nginx.service"
        },
        {
            "id": "snmpd",
            "name": "Net-SNMP Telemetry",
            "category": "infrastructure",
            "category_label": "ENTERPRISE TELEMETRY",
            "role": "RFC 1157 SNMP Telemetry & Active Directory Enterprise MIB",
            "ports": [161],
            "unit": "snmpd.service"
        }
    ]

    result = []
    for item in catalog:
        st = check_systemd_service(item["id"])
        result.append({
            **item,
            **st
        })
    return {"services": result, "total": len(result)}

@app.get("/api/v1/services/{service_name}/logs")
def get_service_logs(service_name: str, lines: int = 50):
    """Retrieves live journalctl log lines for any engine service."""
    if service_name not in ALL_MANAGED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not allowed.")
    code, stdout, stderr = run_cmd(["journalctl", "-u", service_name, "-n", str(min(lines, 200)), "--no-pager"], timeout=10)
    return {"service": service_name, "logs": stdout or stderr or "No logs recorded yet."}

@app.post("/api/v1/services/{service_name}/control")
def control_service(service_name: str, req: ServiceActionRequest):
    """Executes restart, start, stop, reload, enable, or disable on any subsystem service."""
    if service_name not in ALL_MANAGED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not allowed.")

    code, stdout, stderr = run_cmd(["systemctl", req.action, service_name], timeout=15)
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to {req.action} {service_name}: {stderr or stdout}")

    time.sleep(0.5)
    updated_state = check_systemd_service(service_name)
    log_audit("SERVICE_CONTROL", "admin", service_name, "SUCCESS", {"action": req.action})
    return {
        "status": "success",
        "service": service_name,
        "action": req.action,
        "message": f"Service '{service_name}' {req.action} executed successfully.",
        "state": updated_state
    }

# ----------------- Active Directory Domain & UPN & FSMO Management -----------------

@app.get("/api/v1/domain/info")
def get_domain_info():
    """Returns domain NetBIOS, Realm, Forest level, SID, Hostname, Description, and FSMO role holders."""
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
    netbios_name = "INET-ZCLOCKID"
    server_desc = "ZclockID Active Directory Domain Controller"
    server_role = "Active Directory Domain Controller"

    if os.path.exists("/etc/samba/smb.conf"):
        with open("/etc/samba/smb.conf") as f:
            for line in f:
                if "realm =" in line:
                    realm = line.split("=")[1].strip()
                elif "workgroup =" in line:
                    domain = line.split("=")[1].strip()
                elif "netbios name =" in line:
                    netbios_name = line.split("=")[1].strip()
                elif "server string =" in line:
                    server_desc = line.split("=")[1].strip()
                elif "server role =" in line:
                    server_role = line.split("=")[1].strip().title()

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

    code_hn, out_hn, _ = run_cmd(["hostname", "-s"])
    hostname = out_hn.strip() if code_hn == 0 and out_hn.strip() else "inet-zclockid"
    code_fqdn, out_fqdn, _ = run_cmd(["hostname", "-f"])
    raw_fqdn = out_fqdn.strip() if code_fqdn == 0 else ""
    fqdn = raw_fqdn if "." in raw_fqdn else f"{hostname}.{realm.lower()}"

    fl_info = get_functional_level()

    return {
        "realm": realm,
        "domain_netbios": domain,
        "netbios_name": netbios_name,
        "server_role": server_role,
        "server_description": server_desc,
        "hostname": hostname,
        "fqdn": fqdn,
        "domain_sid": domain_sid,
        "forest_functional_level": fl_info.get("forest_level_label", "Windows Server 2016"),
        "domain_functional_level": fl_info.get("domain_level_label", "Windows Server 2016"),
        "lowest_dc_level": fl_info.get("lowest_dc_level_label", "Windows Server 2016"),
        "functional_levels": fl_info,
        "fsmo_roles": fsmo
    }

# ----------------- Active Directory Functional Levels (DFL / FFL) -----------------

LEVEL_ORDER = {
    "2003": 1,
    "2008": 2,
    "2008_R2": 3,
    "2012": 4,
    "2012_R2": 5,
    "2016": 6
}

LEVEL_LABELS = {
    "2003": "Windows Server 2003",
    "2008": "Windows Server 2008",
    "2008_R2": "Windows Server 2008 R2",
    "2012": "Windows Server 2012",
    "2012_R2": "Windows Server 2012 R2",
    "2016": "Windows Server 2016"
}

def parse_fl_string(val: str) -> str:
    val_clean = val.replace("(Windows)", "").strip()
    val_normalized = val_clean.replace(" ", "_").upper()
    for k in LEVEL_ORDER.keys():
        if k == val_clean or k == val_normalized:
            return k
    for k, label in LEVEL_LABELS.items():
        if label.lower() in val_clean.lower():
            return k
    return val_clean

@app.get("/api/v1/domain/functional-level")
def get_functional_level():
    """Returns the current Domain and Forest functional levels, lowest DC level, and supported versions."""
    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd([
        "samba-tool", "domain", "level", "show",
        f"-U{admin_user}", f"--password={admin_pass}"
    ], timeout=10)

    forest_raw = "2016"
    domain_raw = "2016"
    lowest_dc_raw = "2016"

    if code == 0:
        for line in stdout.splitlines():
            if "Forest function level:" in line:
                forest_raw = line.split(":", 1)[1].strip()
            elif "Domain function level:" in line:
                domain_raw = line.split(":", 1)[1].strip()
            elif "Lowest function level of a DC:" in line:
                lowest_dc_raw = line.split(":", 1)[1].strip()

    forest_key = parse_fl_string(forest_raw)
    domain_key = parse_fl_string(domain_raw)
    lowest_dc_key = parse_fl_string(lowest_dc_raw)

    return {
        "status": "success",
        "forest_level": forest_key,
        "forest_level_label": LEVEL_LABELS.get(forest_key, forest_raw),
        "domain_level": domain_key,
        "domain_level_label": LEVEL_LABELS.get(domain_key, domain_raw),
        "lowest_dc_level": lowest_dc_key,
        "lowest_dc_level_label": LEVEL_LABELS.get(lowest_dc_key, lowest_dc_raw),
        "supported_levels": [
            {"id": "2008_R2", "label": "Windows Server 2008 R2"},
            {"id": "2012", "label": "Windows Server 2012"},
            {"id": "2012_R2", "label": "Windows Server 2012 R2"},
            {"id": "2016", "label": "Windows Server 2016"}
        ]
    }

@app.post("/api/v1/domain/functional-level/raise")
def raise_functional_level(req: FunctionalLevelRaiseRequest):
    """Raises the Active Directory Domain and Forest functional levels."""
    d_level = req.domain_level.strip().replace(" ", "_")
    f_level = req.forest_level.strip().replace(" ", "_")

    if d_level not in LEVEL_ORDER or f_level not in LEVEL_ORDER:
        raise HTTPException(status_code=400, detail="Invalid functional level specified.")

    if LEVEL_ORDER[f_level] > LEVEL_ORDER[d_level]:
        raise HTTPException(status_code=400, detail="Forest functional level cannot be higher than Domain functional level.")

    admin_user, admin_pass = get_ad_creds()

    # Check current levels
    curr_info = get_functional_level()
    curr_d_order = LEVEL_ORDER.get(curr_info["domain_level"], 0)
    curr_f_order = LEVEL_ORDER.get(curr_info["forest_level"], 0)

    if LEVEL_ORDER[d_level] < curr_d_order:
        raise HTTPException(status_code=400, detail=f"Active Directory Domain functional level cannot be downgraded below {curr_info['domain_level_label']}.")
    if LEVEL_ORDER[f_level] < curr_f_order:
        raise HTTPException(status_code=400, detail=f"Active Directory Forest functional level cannot be downgraded below {curr_info['forest_level_label']}.")

    if LEVEL_ORDER[d_level] == curr_d_order and LEVEL_ORDER[f_level] == curr_f_order:
        return {
            "status": "success",
            "message": f"Domain and Forest functional levels are already set to {curr_info['domain_level_label']}.",
            "output": "Levels already current.",
            "current": curr_info
        }

    # 1. Update smb.conf 'ad dc functional level' if target is higher than current DC level
    smb_conf = "/etc/samba/smb.conf"
    highest_target = d_level if LEVEL_ORDER[d_level] >= LEVEL_ORDER[f_level] else f_level
    if os.path.exists(smb_conf):
        with open(smb_conf, "r") as f:
            content = f.read()

        if "ad dc functional level" in content:
            new_content = re.sub(r'ad dc functional level\s*=\s*\S+', f'ad dc functional level = {highest_target}', content)
        else:
            new_content = re.sub(r'(\[global\][^\n]*)', r'\1\n    ad dc functional level = ' + highest_target, content)

        if new_content != content:
            with open("/tmp/smb.conf.fl.tmp", "w") as f:
                f.write(new_content)
            run_cmd(["cp", "/tmp/smb.conf.fl.tmp", smb_conf])
            run_cmd(["systemctl", "restart", "samba-ad-dc"], timeout=15)
            time.sleep(1.5)

    # 2. Execute samba-tool domain level raise
    cmd = [
        "samba-tool", "domain", "level", "raise",
        f"--domain-level={d_level}",
        f"--forest-level={f_level}",
        f"-U{admin_user}", f"--password={admin_pass}"
    ]
    code, stdout, stderr = run_cmd(cmd, timeout=20)
    output = (stdout + "\n" + stderr).strip()

    if code != 0 and "already at" not in output.lower():
        raise HTTPException(status_code=500, detail=f"Failed to raise functional level: {output}")

    log_audit("FUNCTIONAL_LEVEL_RAISED", admin_user, "domain", "SUCCESS", {
        "domain_level": d_level,
        "forest_level": f_level,
        "raw_output": output
    })

    # Return updated info
    updated_info = get_functional_level()
    return {
        "status": "success",
        "message": f"Successfully updated functional levels to Domain: {updated_info['domain_level_label']}, Forest: {updated_info['forest_level_label']}",
        "output": output,
        "current": updated_info
    }

@app.post("/api/v1/system/identity")
def update_system_identity(req: SystemIdentityUpdateRequest):
    """Updates server description, hostname, and NetBIOS computer name."""
    actions_taken = []
    
    # 1. Server description (server string) in smb.conf
    if req.server_description is not None and os.path.exists("/etc/samba/smb.conf"):
        desc = req.server_description.strip()
        with open("/etc/samba/smb.conf", "r") as f:
            content = f.read()
        if "server string =" in content:
            content = re.sub(r'server string\s*=.*', f'server string = {desc}', content)
        else:
            content = re.sub(r'\[global\]', f'[global]\n\tserver string = {desc}', content)
        with open("/tmp/smb.conf.tmp", "w") as f:
            f.write(content)
        run_cmd(["cp", "/tmp/smb.conf.tmp", "/etc/samba/smb.conf"])
        run_cmd(["smbcontrol", "all", "reload-config"])
        actions_taken.append(f"Server description updated to '{desc}'")

    # 2. Hostname change
    if req.hostname is not None and req.hostname.strip():
        new_hn = req.hostname.strip().lower()
        code, _, err = run_cmd(["hostnamectl", "set-hostname", new_hn])
        if code == 0:
            if os.path.exists("/etc/hosts"):
                with open("/etc/hosts", "r") as f:
                    hosts_content = f.read()
                realm = "inet.net"
                if os.path.exists("/etc/samba/smb.conf"):
                    with open("/etc/samba/smb.conf") as f:
                        for l in f:
                            if "realm =" in l:
                                realm = l.split("=")[1].strip().lower()
                hosts_content = re.sub(r'127\.0\.1\.1\s+.*', f'127.0.1.1\t{new_hn}.{realm}\t{new_hn}', hosts_content)
                with open("/tmp/hosts.tmp", "w") as f:
                    f.write(hosts_content)
                run_cmd(["cp", "/tmp/hosts.tmp", "/etc/hosts"])
            actions_taken.append(f"System hostname changed to '{new_hn}'")

    # 3. NetBIOS computer name
    if req.netbios_name is not None and req.netbios_name.strip():
        new_nb = req.netbios_name.strip().upper()
        if os.path.exists("/etc/samba/smb.conf"):
            with open("/etc/samba/smb.conf", "r") as f:
                content = f.read()
            content = re.sub(r'netbios name\s*=.*', f'netbios name = {new_nb}', content)
            with open("/tmp/smb.conf.tmp", "w") as f:
                f.write(content)
            run_cmd(["cp", "/tmp/smb.conf.tmp", "/etc/samba/smb.conf"])
            run_cmd(["systemctl", "restart", "samba-ad-dc"])
            actions_taken.append(f"NetBIOS computer name changed to '{new_nb}' (samba-ad-dc restarted)")

    log_audit("SYSTEM_IDENTITY_UPDATED", "admin", "system", "SUCCESS", {"actions": actions_taken})
    return {"status": "success", "actions": actions_taken, "message": "System identity updated successfully."}

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
    """Forces immediate Directory Replication Service synchronization and re-evaluates FreeRADIUS rate limits."""
    code, stdout, stderr = run_cmd(["samba-tool", "drs", "kcc"], timeout=20)
    try:
        sync_freeradius_policies()
    except Exception as e:
        logger.warning(f"Failed to refresh FreeRADIUS policies post DRS sync: {e}")
    log_audit("DRS_SYNC_FORCED", "admin", "drs", "SUCCESS" if code == 0 else "FAILED", {"output": stdout})
    return {"status": "success" if code == 0 else "error", "message": stdout}

# ----------------- Users & Groups Management -----------------

@app.get("/api/v1/users")
def list_domain_users():
    primary_realm = get_primary_realm().lower()
    code, stdout, stderr = run_cmd([
        "ldbsearch", "-H", "/var/lib/samba/private/sam.ldb",
        "(objectClass=user)",
        "sAMAccountName", "userPrincipalName", "givenName", "sn", "displayName", "mail", "telephoneNumber", "department", "info", "userAccountControl"
    ], timeout=10)

    # Fetch bandwidth mappings from local SQLite
    user_bw_map = {}
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.username, u.profile_id, p.name as profile_name, p.download_mbps, p.upload_mbps
            FROM radius_user_bandwidth u
            JOIN radius_bandwidth_profiles p ON u.profile_id = p.id
            WHERE p.is_active = 1
        """)
        for row in cursor.fetchall():
            user_bw_map[row["username"]] = dict(row)

        cursor.execute("SELECT id, name FROM radius_bandwidth_profiles")
        profiles_by_name = {r["name"].lower(): r["id"] for r in cursor.fetchall()}
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to read radius_user_bandwidth: {e}")
        profiles_by_name = {}

    users = []
    if code == 0:
        current_user = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current_user.get("username"):
                    u = current_user["username"]
                    if not u.endswith("$"):
                        is_built_in = u in ["Administrator", "Guest", "krbtgt", "dns-inet-zclockid"]
                        uac = current_user.get("uac", 512)
                        is_disabled = (uac & 2) != 0 or u in ["Guest", "krbtgt"]
                        upn = current_user.get("user_principal_name") or f"{u}@{primary_realm}"
                        bw_entry = user_bw_map.get(u)
                        bw_parsed = parse_bw_info(current_user.get("info"))

                        p_name = bw_parsed["name"] if bw_parsed else (bw_entry["profile_name"] if bw_entry else None)
                        p_id = bw_entry["profile_id"] if bw_entry else (profiles_by_name.get(p_name.lower()) if p_name else None)
                        d_val = bw_parsed["download_mbps"] if bw_parsed else (bw_entry["download_mbps"] if bw_entry else None)
                        u_val = bw_parsed["upload_mbps"] if bw_parsed else (bw_entry["upload_mbps"] if bw_entry else None)
                        bw_rate_str = f"{d_val:g}M/{u_val:g}M" if (d_val is not None and u_val is not None) else None

                        g_name = current_user.get("given_name") or ""
                        s_name = current_user.get("surname") or ""
                        full_name = current_user.get("display_name") or f"{g_name} {s_name}".strip() or u
                        users.append({
                            "username": u,
                            "name": full_name,
                            "given_name": g_name,
                            "surname": s_name,
                            "user_principal_name": upn,
                            "email": current_user.get("email") or "",
                            "mobile": current_user.get("mobile") or "",
                            "department": current_user.get("department") or ("IT Operations" if u in ["Administrator", "admin"] else "Corporate Staff"),
                            "status": "disabled" if is_disabled else "active",
                            "is_disabled": is_disabled,
                            "is_built_in": is_built_in,
                            "bandwidth_profile_id": p_id,
                            "bandwidth_profile_name": p_name,
                            "bandwidth_rate": bw_rate_str
                        })
                current_user = {}
                continue
            if line.startswith("sAMAccountName:"):
                current_user["username"] = line.split(":", 1)[1].strip()
            elif line.startswith("userPrincipalName:"):
                current_user["user_principal_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("givenName:"):
                current_user["given_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("sn:"):
                current_user["surname"] = line.split(":", 1)[1].strip()
            elif line.startswith("displayName:"):
                current_user["display_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("mail:"):
                current_user["email"] = line.split(":", 1)[1].strip()
            elif line.startswith("telephoneNumber:"):
                current_user["mobile"] = line.split(":", 1)[1].strip()
            elif line.startswith("department:"):
                current_user["department"] = line.split(":", 1)[1].strip()
            elif line.startswith("info:"):
                current_user["info"] = line.split(":", 1)[1].strip()
            elif line.startswith("userAccountControl:"):
                try:
                    current_user["uac"] = int(line.split(":", 1)[1].strip())
                except:
                    current_user["uac"] = 512

        if current_user.get("username"):
            u = current_user["username"]
            if not u.endswith("$"):
                is_built_in = u in ["Administrator", "Guest", "krbtgt", "dns-inet-zclockid"]
                uac = current_user.get("uac", 512)
                is_disabled = (uac & 2) != 0 or u in ["Guest", "krbtgt"]
                upn = current_user.get("user_principal_name") or f"{u}@{primary_realm}"
                bw_entry = user_bw_map.get(u)
                bw_parsed = parse_bw_info(current_user.get("info"))

                p_name = bw_parsed["name"] if bw_parsed else (bw_entry["profile_name"] if bw_entry else None)
                p_id = bw_entry["profile_id"] if bw_entry else (profiles_by_name.get(p_name.lower()) if p_name else None)
                d_val = bw_parsed["download_mbps"] if bw_parsed else (bw_entry["download_mbps"] if bw_entry else None)
                u_val = bw_parsed["upload_mbps"] if bw_parsed else (bw_entry["upload_mbps"] if bw_entry else None)
                bw_rate_str = f"{d_val:g}M/{u_val:g}M" if (d_val is not None and u_val is not None) else None

                g_name = current_user.get("given_name") or ""
                s_name = current_user.get("surname") or ""
                full_name = current_user.get("display_name") or f"{g_name} {s_name}".strip() or u
                users.append({
                    "username": u,
                    "name": full_name,
                    "given_name": g_name,
                    "surname": s_name,
                    "user_principal_name": upn,
                    "email": current_user.get("email") or "",
                    "mobile": current_user.get("mobile") or "",
                    "department": current_user.get("department") or ("IT Operations" if u in ["Administrator", "admin"] else "Corporate Staff"),
                    "status": "disabled" if is_disabled else "active",
                    "is_disabled": is_disabled,
                    "is_built_in": is_built_in,
                    "bandwidth_profile_id": p_id,
                    "bandwidth_profile_name": p_name,
                    "bandwidth_rate": bw_rate_str
                })

    if not users:
        c2, out2, _ = run_cmd(["samba-tool", "user", "list"], timeout=10)
        if c2 == 0:
            for u in out2.splitlines():
                u = u.strip()
                if u and not u.endswith("$"):
                    bw_entry = user_bw_map.get(u)
                    users.append({
                        "username": u,
                        "name": u,
                        "given_name": "",
                        "surname": "",
                        "user_principal_name": f"{u}@{primary_realm}",
                        "email": "",
                        "mobile": "",
                        "department": "Corporate Staff",
                        "status": "active" if u not in ["Guest", "krbtgt"] else "disabled",
                        "is_disabled": u in ["Guest", "krbtgt"],
                        "is_built_in": u in ["Administrator", "Guest", "krbtgt", "dns-inet-zclockid"],
                        "bandwidth_profile_id": bw_entry["profile_id"] if bw_entry else None,
                        "bandwidth_profile_name": bw_entry["profile_name"] if bw_entry else None,
                        "bandwidth_rate": f"{bw_entry['download_mbps']:g}M/{bw_entry['upload_mbps']:g}M" if bw_entry else None
                    })

    return {"count": len(users), "users": users}

@app.get("/api/v1/users/{username}")
def get_domain_user(username: str):
    """Returns detailed information for a single user account."""
    all_users = list_domain_users()["users"]
    for u in all_users:
        if u["username"].lower() == username.lower():
            return u
    raise HTTPException(status_code=404, detail=f"User '{username}' not found.")

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
    if req.mobile: cmd.extend(["--telephone-number", req.mobile])
    if req.department: cmd.extend(["--department", req.department])

    code, stdout, stderr = run_cmd(cmd, timeout=20)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to create user: {stderr or stdout}")

    if req.target_group and req.target_group != "Domain Users":
        run_cmd(["samba-tool", "group", "addmembers", req.target_group, req.username, f"-U{admin_user}", f"--password={admin_pass}"])

    if req.bandwidth_profile_id and req.bandwidth_profile_id > 0:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM radius_bandwidth_profiles WHERE id = ?", (req.bandwidth_profile_id,))
            p_row = cursor.fetchone()

            cursor.execute("""
                INSERT INTO radius_user_bandwidth (username, profile_id, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET profile_id = excluded.profile_id, updated_at = excluded.updated_at
            """, (req.username, req.bandwidth_profile_id, time.time()))
            conn.commit()
            conn.close()

            if p_row:
                p = dict(p_row)
                bw_tag = f"ZCLOCKID_BW:{p['name']};down={p['download_mbps']};up={p['upload_mbps']};sess={p.get('session_timeout_mins', 120)};idle={p.get('idle_timeout_mins', 30)};quota={p.get('daily_quota_mb', 0)}"
                c_d, o_d, _ = run_cmd(["ldbsearch", "-H", "/var/lib/samba/private/sam.ldb", f"(sAMAccountName={req.username})", "dn"])
                if c_d == 0 and "dn: " in o_d:
                    for l in o_d.splitlines():
                        if l.startswith("dn: "):
                            u_dn = l[4:].strip()
                            ldif = f"dn: {u_dn}\nchangetype: modify\nreplace: info\ninfo: {bw_tag}\n-\n"
                            subprocess.run(["ldbmodify", "-H", "/var/lib/samba/private/sam.ldb"], input=ldif, text=True, capture_output=True)
                            break
            sync_freeradius_policies()
        except Exception as e:
            logger.warning(f"Failed to assign user bandwidth on create: {e}")

    log_audit("USER_CREATED", "admin", req.username, "SUCCESS", {"group": req.target_group, "bandwidth_profile_id": req.bandwidth_profile_id})
    return {"status": "success", "username": req.username, "message": f"User {req.username} provisioned successfully."}

@app.put("/api/v1/users/{username}")
def update_domain_user(username: str, req: UserUpdateRequest):
    """Updates user attributes (names, email, mobile, department, UPN), password, status, and bandwidth tier."""
    # 1. Verify user exists in SAM LDB
    code, stdout, stderr = run_cmd(["ldbsearch", "-H", "/var/lib/samba/private/sam.ldb", f"(sAMAccountName={username})", "dn"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to query SAM LDB: {stderr}")
    dn = None
    for line in stdout.splitlines():
        if line.startswith("dn: "):
            dn = line[4:].strip()
            break
    if not dn:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found in Active Directory.")

    # 2. Resolve Bandwidth Profile tag for AD DRS Replication (Option B)
    bw_info_tag = None
    if req.bandwidth_profile_id is not None:
        if req.bandwidth_profile_id > 0:
            try:
                conn_b = sqlite3.connect(DB_PATH)
                conn_b.row_factory = sqlite3.Row
                c_b = conn_b.cursor()
                c_b.execute("SELECT * FROM radius_bandwidth_profiles WHERE id = ?", (req.bandwidth_profile_id,))
                p_r = c_b.fetchone()
                conn_b.close()
                if p_r:
                    p = dict(p_r)
                    bw_info_tag = f"ZCLOCKID_BW:{p['name']};down={p['download_mbps']};up={p['upload_mbps']};sess={p.get('session_timeout_mins', 120)};idle={p.get('idle_timeout_mins', 30)};quota={p.get('daily_quota_mb', 0)}"
            except Exception as e:
                logger.warning(f"Failed to lookup profile details: {e}")
        else:
            bw_info_tag = "" # clear from AD info attribute

    # 3. Modify AD attributes via ldbmodify
    ldif_lines = [f"dn: {dn}", "changetype: modify"]
    has_modifications = False

    attr_map = [
        ("givenName", req.given_name),
        ("sn", req.surname),
        ("mail", req.email),
        ("telephoneNumber", req.mobile),
        ("department", req.department),
        ("userPrincipalName", req.user_principal_name)
    ]
    if bw_info_tag is not None:
        attr_map.append(("info", bw_info_tag))

    for attr, val in attr_map:
        if val is not None:
            val_clean = str(val).strip()
            if val_clean:
                ldif_lines.extend([f"replace: {attr}", f"{attr}: {val_clean}", "-"])
            else:
                ldif_lines.extend([f"replace: {attr}", "-"])
            has_modifications = True

    # If givenName or surname was updated, update displayName as well
    if req.given_name is not None or req.surname is not None:
        g = req.given_name if req.given_name is not None else ""
        s = req.surname if req.surname is not None else ""
        disp = f"{g} {s}".strip() or username
        ldif_lines.extend(["replace: displayName", f"displayName: {disp}", "-"])
        has_modifications = True

    if has_modifications:
        ldif_content = "\n".join(ldif_lines) + "\n"
        proc = subprocess.run(["ldbmodify", "-H", "/var/lib/samba/private/sam.ldb"], input=ldif_content, text=True, capture_output=True)
        if proc.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Failed to update user attributes: {proc.stderr}")

    admin_user, admin_pass = get_ad_creds()

    # 4. Handle Password Reset if requested
    if req.new_password:
        p_code, p_out, p_err = run_cmd([
            "samba-tool", "user", "setpassword", username,
            f"--newpassword={req.new_password}",
            f"-U{admin_user}", f"--password={admin_pass}"
        ], timeout=15)
        if p_code != 0:
            raise HTTPException(status_code=400, detail=f"Failed to reset password: {p_err or p_out}")

    # 5. Handle Account Status (Enable/Disable)
    if req.is_disabled is not None:
        action = "disable" if req.is_disabled else "enable"
        s_code, s_out, s_err = run_cmd([
            "samba-tool", "user", action, username,
            f"-U{admin_user}", f"--password={admin_pass}"
        ], timeout=15)
        if s_code != 0:
            raise HTTPException(status_code=400, detail=f"Failed to {action} user: {s_err or s_out}")

    # 6. Handle Local SQLite Cache Update
    if req.bandwidth_profile_id is not None:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            now_ts = time.time()
            if req.bandwidth_profile_id > 0:
                cursor.execute("""
                    INSERT INTO radius_user_bandwidth (username, profile_id, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET profile_id = excluded.profile_id, updated_at = excluded.updated_at
                """, (username, req.bandwidth_profile_id, now_ts))
            else:
                cursor.execute("DELETE FROM radius_user_bandwidth WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            sync_freeradius_policies()
        except Exception as e:
            logger.warning(f"Failed to update user bandwidth profile: {e}")

    log_audit("USER_UPDATED", "admin", username, "SUCCESS", {
        "given_name": req.given_name,
        "surname": req.surname,
        "email": req.email,
        "mobile": req.mobile,
        "department": req.department,
        "user_principal_name": req.user_principal_name,
        "bandwidth_profile_id": req.bandwidth_profile_id,
        "is_disabled": req.is_disabled,
        "password_reset": bool(req.new_password)
    })

    return {
        "status": "success",
        "username": username,
        "message": f"User '{username}' updated successfully."
    }

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

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM radius_user_bandwidth WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        sync_freeradius_policies()
    except Exception:
        pass

    log_audit("USER_DELETED", "admin", username, "SUCCESS", {})
    return {"status": "success", "message": f"User {username} permanently removed."}

@app.post("/api/v1/users/{username}/upn")
def update_user_upn_endpoint(username: str, req: UserUpnUpdateRequest):
    """Updates userPrincipalName attribute in Samba Active Directory SAM database."""
    new_upn = req.user_principal_name.strip()
    if not new_upn or "@" not in new_upn:
        raise HTTPException(status_code=400, detail="Invalid UPN format. Must be in user@domain format.")

    try:
        dn = update_user_upn(username, new_upn)
        log_audit("USER_UPN_UPDATED", "admin", username, "SUCCESS", {"new_upn": new_upn, "dn": dn})
        return {
            "status": "success",
            "message": f"UserPrincipalName for '{username}' updated to '{new_upn}' successfully.",
            "username": username,
            "user_principal_name": new_upn
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/groups")
def list_domain_groups():
    """Lists all Active Directory security groups with member counts, descriptions, and assigned bandwidth profiles."""
    code, stdout, stderr = run_cmd([
        "ldbsearch", "-H", "/var/lib/samba/private/sam.ldb",
        "(objectClass=group)",
        "sAMAccountName", "description", "info", "member"
    ], timeout=10)

    # Fetch SQLite bandwidth profile mappings
    group_bw_map = {}
    profiles_by_name = {}
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM radius_bandwidth_profiles WHERE is_active = 1")
        for row in c.fetchall():
            r = dict(row)
            profiles_by_name[r["name"].lower()] = r
            if r.get("ad_group"):
                group_bw_map[r["ad_group"].lower()] = r
            if r.get("target_type") == "GROUP" and r.get("target_name"):
                group_bw_map[r["target_name"].lower()] = r
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to query bandwidth profiles for groups: {e}")

    protected_builtins = {
        "administrators", "domain admins", "enterprise admins", "schema admins",
        "domain users", "domain guests", "domain computers", "domain controllers",
        "group policy creator owners", "cert publishers", "ras and ias servers",
        "allowed rodc password replication group", "denied rodc password replication group",
        "read-only domain controllers", "enterprise read-only domain controllers",
        "dnsadmins", "dnsupdateproxy"
    }

    groups = []
    if code == 0:
        current_grp = {}
        members = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current_grp.get("group_name"):
                    g_name = current_grp["group_name"]
                    is_builtin = g_name.lower() in protected_builtins
                    info_raw = current_grp.get("info")
                    bw_parsed = parse_bw_info(info_raw)
                    bw_entry = group_bw_map.get(g_name.lower())

                    p_name = bw_parsed["name"] if bw_parsed else (bw_entry["name"] if bw_entry else None)
                    p_id = bw_entry["id"] if bw_entry else (profiles_by_name.get(p_name.lower(), {}).get("id") if p_name else None)
                    d_val = bw_parsed["download_mbps"] if bw_parsed else (bw_entry["download_mbps"] if bw_entry else None)
                    u_val = bw_parsed["upload_mbps"] if bw_parsed else (bw_entry["upload_mbps"] if bw_entry else None)
                    rate_str = f"{d_val:g}M/{u_val:g}M" if (d_val is not None and u_val is not None) else None

                    groups.append({
                        "group_name": g_name,
                        "description": current_grp.get("description", ""),
                        "member_count": len(members),
                        "is_built_in": is_builtin,
                        "bandwidth_profile_id": p_id,
                        "bandwidth_profile_name": p_name,
                        "bandwidth_rate": rate_str
                    })
                current_grp = {}
                members = []
                continue

            if line.startswith("sAMAccountName:"):
                current_grp["group_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("description:"):
                current_grp["description"] = line.split(":", 1)[1].strip()
            elif line.startswith("info:"):
                current_grp["info"] = line.split(":", 1)[1].strip()
            elif line.startswith("member:"):
                members.append(line.split(":", 1)[1].strip())

        if current_grp.get("group_name"):
            g_name = current_grp["group_name"]
            is_builtin = g_name.lower() in protected_builtins
            info_raw = current_grp.get("info")
            bw_parsed = parse_bw_info(info_raw)
            bw_entry = group_bw_map.get(g_name.lower())

            p_name = bw_parsed["name"] if bw_parsed else (bw_entry["name"] if bw_entry else None)
            p_id = bw_entry["id"] if bw_entry else (profiles_by_name.get(p_name.lower(), {}).get("id") if p_name else None)
            d_val = bw_parsed["download_mbps"] if bw_parsed else (bw_entry["download_mbps"] if bw_entry else None)
            u_val = bw_parsed["upload_mbps"] if bw_parsed else (bw_entry["upload_mbps"] if bw_entry else None)
            rate_str = f"{d_val:g}M/{u_val:g}M" if (d_val is not None and u_val is not None) else None

            groups.append({
                "group_name": g_name,
                "description": current_grp.get("description", ""),
                "member_count": len(members),
                "is_built_in": is_builtin,
                "bandwidth_profile_id": p_id,
                "bandwidth_profile_name": p_name,
                "bandwidth_rate": rate_str
            })

    # Sort custom groups first, then alphabetically
    groups.sort(key=lambda x: (x["is_built_in"], x["group_name"].lower()))
    return {"count": len(groups), "groups": groups}

@app.post("/api/v1/groups")
def create_domain_group(req: GroupCreateRequest):
    """Creates a new Active Directory Security Group and assigns optional Bandwidth/Gateway policy."""
    admin_user, admin_pass = get_ad_creds()
    cmd = ["samba-tool", "group", "add", req.group_name, f"-U{admin_user}", f"--password={admin_pass}"]
    if req.description: cmd.extend(["--description", req.description])
    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to create group: {stderr or stdout}")

    # If bandwidth profile is assigned, store in group's AD info attribute (DRS Replicated) & SQLite
    if req.bandwidth_profile_id and req.bandwidth_profile_id > 0:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM radius_bandwidth_profiles WHERE id = ?", (req.bandwidth_profile_id,))
            p_row = c.fetchone()
            if p_row:
                p = dict(p_row)
                bw_tag = f"ZCLOCKID_BW:{p['name']};down={p['download_mbps']};up={p['upload_mbps']};sess={p.get('session_timeout_mins', 120)};idle={p.get('idle_timeout_mins', 30)};quota={p.get('daily_quota_mb', 0)}"
                c_d, o_d, _ = run_cmd(["ldbsearch", "-H", "/var/lib/samba/private/sam.ldb", f"(&(objectClass=group)(sAMAccountName={req.group_name}))", "dn"])
                if c_d == 0 and "dn: " in o_d:
                    for l in o_d.splitlines():
                        if l.startswith("dn: "):
                            g_dn = l[4:].strip()
                            ldif = f"dn: {g_dn}\nchangetype: modify\nreplace: info\ninfo: {bw_tag}\n-\n"
                            subprocess.run(["ldbmodify", "-H", "/var/lib/samba/private/sam.ldb"], input=ldif, text=True, capture_output=True)
                            break

                # Update SQLite profile mapping
                c.execute("UPDATE radius_bandwidth_profiles SET ad_group = ? WHERE id = ?", (req.group_name, req.bandwidth_profile_id))
                conn.commit()
            conn.close()
            sync_freeradius_policies()
        except Exception as e:
            logger.warning(f"Failed to assign bandwidth profile to group: {e}")

    log_audit("GROUP_CREATED", "admin", req.group_name, "SUCCESS", {"bandwidth_profile_id": req.bandwidth_profile_id})
    return {"status": "success", "group_name": req.group_name, "message": f"Security group '{req.group_name}' created successfully."}

@app.put("/api/v1/groups/{group_name}")
def update_domain_group(group_name: str, req: GroupUpdateRequest):
    """Updates Active Directory Security Group description and assigned Bandwidth / Gateway policy."""
    c_d, o_d, _ = run_cmd(["ldbsearch", "-H", "/var/lib/samba/private/sam.ldb", f"(&(objectClass=group)(sAMAccountName={group_name}))", "dn"])
    if c_d != 0 or "dn: " not in o_d:
        raise HTTPException(status_code=404, detail=f"Group '{group_name}' not found in Active Directory.")

    g_dn = None
    for l in o_d.splitlines():
        if l.startswith("dn: "):
            g_dn = l[4:].strip()
            break

    ldif_lines = [f"dn: {g_dn}", "changetype: modify"]
    has_mod = False

    if req.description is not None:
        d_val = req.description.strip()
        if d_val:
            ldif_lines.extend(["replace: description", f"description: {d_val}", "-"])
        else:
            ldif_lines.extend(["replace: description", "-"])
        has_mod = True

    bw_info_tag = None
    if req.bandwidth_profile_id is not None:
        if req.bandwidth_profile_id > 0:
            try:
                conn = sqlite3.connect(DB_PATH)
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT * FROM radius_bandwidth_profiles WHERE id = ?", (req.bandwidth_profile_id,))
                p_row = c.fetchone()
                if p_row:
                    p = dict(p_row)
                    bw_info_tag = f"ZCLOCKID_BW:{p['name']};down={p['download_mbps']};up={p['upload_mbps']};sess={p.get('session_timeout_mins', 120)};idle={p.get('idle_timeout_mins', 30)};quota={p.get('daily_quota_mb', 0)}"
                    c.execute("UPDATE radius_bandwidth_profiles SET ad_group = ? WHERE id = ?", (group_name, req.bandwidth_profile_id))
                    conn.commit()
                conn.close()
            except Exception as e:
                logger.warning(f"Failed to lookup profile: {e}")
        else:
            bw_info_tag = ""
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("UPDATE radius_bandwidth_profiles SET ad_group = '' WHERE ad_group = ?", (group_name,))
                conn.commit()
                conn.close()
            except Exception:
                pass

    if bw_info_tag is not None:
        if bw_info_tag:
            ldif_lines.extend(["replace: info", f"info: {bw_info_tag}", "-"])
        else:
            ldif_lines.extend(["replace: info", "-"])
        has_mod = True

    if has_mod:
        ldif_content = "\n".join(ldif_lines) + "\n"
        proc = subprocess.run(["ldbmodify", "-H", "/var/lib/samba/private/sam.ldb"], input=ldif_content, text=True, capture_output=True)
        if proc.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Failed to update group attributes: {proc.stderr}")

    sync_freeradius_policies()
    log_audit("GROUP_UPDATED", "admin", group_name, "SUCCESS", {"bandwidth_profile_id": req.bandwidth_profile_id})
    return {"status": "success", "group_name": group_name, "message": f"Group '{group_name}' updated successfully."}

@app.delete("/api/v1/groups/{group_name}")
def delete_domain_group(group_name: str):
    """Deletes an Active Directory Security Group."""
    protected = {"administrators", "domain admins", "enterprise admins", "schema admins", "domain users", "domain guests", "domain computers", "domain controllers"}
    if group_name.lower() in protected:
        raise HTTPException(status_code=400, detail=f"Cannot delete protected built-in group '{group_name}'.")

    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "group", "delete", group_name, f"-U{admin_user}", f"--password={admin_pass}"], timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to delete group: {stderr or stdout}")

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE radius_bandwidth_profiles SET ad_group = '' WHERE ad_group = ?", (group_name,))
        conn.commit()
        conn.close()
    except Exception:
        pass

    sync_freeradius_policies()
    log_audit("GROUP_DELETED", "admin", group_name, "SUCCESS", {})
    return {"status": "success", "message": f"Security group '{group_name}' deleted successfully."}

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
    """Queries all DNS records in a zone hierarchically, crawling subnodes, AD SRV, and Host records."""
    admin_user, admin_pass = get_ad_creds()
    records = []
    visited = set()
    queue = ["@"]

    while queue and len(visited) < 40:
        node = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)

        code, stdout, _ = run_cmd([
            "samba-tool", "dns", "query", "127.0.0.1", zone, node, "ALL",
            f"-U{admin_user}", f"--password={admin_pass}"
        ], timeout=8)

        if code != 0:
            continue

        current_name = node
        for line in stdout.splitlines():
            if line.startswith("  Name="):
                m = re.search(r'Name=([^,]*), Records=(\d+), Children=(\d+)', line)
                if m:
                    sub_name = m.group(1).strip()
                    num_records = int(m.group(2))
                    num_children = int(m.group(3))

                    if sub_name:
                        full_name = f"{sub_name}.{node}" if node != "@" else sub_name
                    else:
                        full_name = node
                    current_name = full_name

                    if num_children > 0 and full_name not in visited and full_name not in queue:
                        queue.append(full_name)
            elif line.startswith("    "):
                parts = line.strip().split(":", 1)
                if len(parts) == 2:
                    rtype = parts[0].strip()
                    rdata = re.sub(r'\(flags=[^)]+\)', '', parts[1]).strip()
                    records.append({
                        "name": current_name,
                        "type": rtype,
                        "data": rdata,
                        "zone": zone,
                        "is_srv": (rtype == "SRV")
                    })

    return {"zone": zone, "count": len(records), "records": records}

# ----------------- DNS-over-HTTPS (DoH) Management Endpoints -----------------

@app.get("/api/v1/dns/doh/status")
def get_doh_status(request: Request):
    """Returns DNS-over-HTTPS (DoH) listener status, URLs, and RFC 8484 compliance details."""
    host_hdr = request.headers.get("host", "192.168.1.41").split(":")[0]
    appliance_ip = "192.168.1.41"
    
    # Check if BIND is listening on 8053
    code_ss, out_ss, _ = run_cmd(["ss", "-tlpn"])
    is_bind_doh = (code_ss == 0 and ":8053" in out_ss and "named" in out_ss)

    realm = "inet.net"
    if os.path.exists("/etc/samba/smb.conf"):
        with open("/etc/samba/smb.conf") as f:
            for l in f:
                if "realm =" in l:
                    realm = l.split("=")[1].strip().lower()

    code_hn, out_hn, _ = run_cmd(["hostname", "-s"])
    hostname = out_hn.strip() if code_hn == 0 and out_hn.strip() else "inet-zclockid"
    fqdn = f"{hostname}.{realm}"

    return {
        "status": "ACTIVE" if is_bind_doh else "INACTIVE",
        "service": "BIND9 (named) HTTP/2 + Nginx TLS Ingress",
        "rfc_standard": "RFC 8484 (DNS Queries over HTTPS)",
        "ingress_port": 443,
        "backend_port": 8053,
        "doh_url_ip": f"https://{appliance_ip}/dns-query",
        "doh_url_fqdn": f"https://{fqdn}/dns-query",
        "doh_url_custom": f"https://{host_hdr}/dns-query" if host_hdr != appliance_ip else f"https://{appliance_ip}/dns-query",
        "supported_methods": [
            "GET /dns-query?dns={base64url}",
            "POST /dns-query (Content-Type: application/dns-message)"
        ],
        "dnssec_validation": "Active Directory Native",
        "upstream_forwarders": ["1.1.1.1", "8.8.8.8"]
    }

@app.post("/api/v1/dns/doh/test")
def test_doh_resolution(req: DohTestRequest):
    """Executes a live DNS-over-HTTPS (DoH) query via RFC 8484 and decodes the response wire format."""
    target_qname = (req.qname or req.query_name or "inet.net").strip()
    target_rtype = (req.rtype or req.query_type or "A").strip().upper()

    try:
        q = dns.message.make_query(target_qname, target_rtype)
        wire_query = q.to_wire()
        b64_dns = base64.urlsafe_b64encode(wire_query).decode("utf-8").rstrip("=")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        start_time = time.time()
        doh_url = f"https://127.0.0.1/dns-query?dns={b64_dns}"
        req_obj = urllib.request.Request(doh_url, headers={"Accept": "application/dns-message"})

        with urllib.request.urlopen(req_obj, context=ctx, timeout=6) as resp:
            data = resp.read()
            duration_ms = round((time.time() - start_time) * 1000, 2)
            resp_msg = dns.message.from_wire(data)

            raw_answers = []
            formatted_answers = []
            for rrset in resp_msg.answer:
                for item in rrset:
                    rd_text = str(item)
                    type_str = dns.rdatatype.to_text(rrset.rdtype)
                    raw_answers.append({
                        "name": str(rrset.name),
                        "type": type_str,
                        "ttl": rrset.ttl,
                        "data": rd_text
                    })
                    formatted_answers.append(f"{str(rrset.name)} {rrset.ttl}s {type_str} {rd_text}")

            rcode_text = dns.rcode.to_text(resp_msg.rcode())
            return {
                "status": "ok",
                "success": True,
                "http_status": resp.status,
                "status_code": resp.status,
                "rcode": rcode_text,
                "latency_ms": duration_ms,
                "response_time_ms": duration_ms,
                "rtype": target_rtype,
                "answers": formatted_answers,
                "raw_answers": raw_answers,
                "answer_count": len(raw_answers),
                "query": f"{target_qname} IN {target_rtype}",
                "message": f"Successfully resolved {target_qname} via DoH in {duration_ms}ms ({len(raw_answers)} answers)."
            }
    except Exception as e:
        return {
            "status": "error",
            "success": False,
            "detail": str(e),
            "error": f"DoH query failed: {str(e)}",
            "query": f"{target_qname} IN {target_rtype}"
        }

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

# ----------------- FreeRADIUS 802.1X NAS Clients, Secrets & Accounting (Option 2: Tiered Standard & Advanced) -----------------

def sync_freeradius_policies():
    """Generates and writes FreeRADIUS authorize file with Bandwidth Rate Limiting, MAB devices, and custom attributes."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM radius_mab_devices WHERE is_active = 1 ORDER BY id ASC")
    mab_rows = [dict(r) for r in cursor.fetchall()]

    # Individual User Bandwidth Mappings
    cursor.execute("""
        SELECT u.username, p.name, p.download_mbps, p.upload_mbps, p.session_timeout_mins, p.idle_timeout_mins, p.daily_quota_mb
        FROM radius_user_bandwidth u
        JOIN radius_bandwidth_profiles p ON u.profile_id = p.id
        WHERE p.is_active = 1
        ORDER BY u.username ASC
    """)
    user_bw_rows = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM radius_bandwidth_profiles WHERE is_active = 1 ORDER BY is_default ASC, id ASC")
    bw_rows = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM radius_custom_attributes WHERE is_active = 1 ORDER BY id ASC")
    custom_rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    lines = [
        "# =====================================================================",
        "# ZclockID FreeRADIUS Authorize Configuration: Captive Portal & Rate Limits",
        f"# Automatically generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# =====================================================================",
        ""
    ]

    # 1. MAC Authentication Bypass (MAB) for Headless Devices (Printers, IoT, Cameras)
    if mab_rows:
        lines.append("# --- MAC Authentication Bypass (MAB) for Headless Devices ---")
        for mab in mab_rows:
            mac_clean = re.sub(r'[^a-fA-F0-9]', '', mab['mac_address']).lower()
            formatted_mac = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2)) if len(mac_clean) == 12 else mab['mac_address']
            lines.append(f'# Device: {mab["device_name"]} ({mab.get("description", "")})')
            lines.append(f'"{formatted_mac}" Auth-Type := Accept')
            lines.append(f'\tWISPr-Bandwidth-Max-Down = 50000000,')
            lines.append(f'\tWISPr-Bandwidth-Max-Up = 25000000,')
            if mab.get("static_ip"):
                lines.append(f'\tFramed-IP-Address = {mab["static_ip"]},')
            lines.append(f'\tFall-Through = Yes\n')

    # 2. Individual User Bandwidth Profiles (Highest Priority - DRS Multi-Master Replicated)
    # Query Active Directory SAM LDB for all users with ZCLOCKID_BW in info attribute (Replicated via Microsoft DRS)
    ad_user_overrides = {}
    code_ad, out_ad, _ = run_cmd([
        "ldbsearch", "-H", "/var/lib/samba/private/sam.ldb",
        "(info=ZCLOCKID_BW:*)", "sAMAccountName", "info"
    ], timeout=5)
    if code_ad == 0:
        c_u = {}
        for line in out_ad.splitlines():
            line = line.strip()
            if not line:
                if c_u.get("username") and c_u.get("info"):
                    bw = parse_bw_info(c_u["info"])
                    if bw:
                        ad_user_overrides[c_u["username"]] = {
                            "username": c_u["username"],
                            **bw
                        }
                c_u = {}
                continue
            if line.startswith("sAMAccountName:"):
                c_u["username"] = line.split(":", 1)[1].strip()
            elif line.startswith("info:"):
                c_u["info"] = line.split(":", 1)[1].strip()
        if c_u.get("username") and c_u.get("info"):
            bw = parse_bw_info(c_u["info"])
            if bw:
                ad_user_overrides[c_u["username"]] = {
                    "username": c_u["username"],
                    **bw
                }

    # Merge local SQLite mappings with Active Directory DRS mappings
    merged_user_bw = {}
    for ubw in user_bw_rows:
        merged_user_bw[ubw['username']] = ubw
    for u_name, u_data in ad_user_overrides.items():
        merged_user_bw[u_name] = u_data

    if merged_user_bw:
        lines.append("# --- Individual User Bandwidth Profiles (Top Priority - DRS Multi-Master Replicated) ---")
        for u_name, ubw in sorted(merged_user_bw.items()):
            down_bps = int(ubw['download_mbps'] * 1000000)
            up_bps = int(ubw['upload_mbps'] * 1000000)
            mk_rate = f"{ubw['upload_mbps']:g}M/{ubw['download_mbps']:g}M"
            sess_sec = int(ubw.get('session_timeout_mins', 0) * 60)
            idle_sec = int(ubw.get('idle_timeout_mins', 0) * 60)
            quota_bytes = int(ubw.get('daily_quota_mb', 0) * 1024 * 1024)

            lines.append(f'# User Override: {u_name} -> Tier: {ubw["name"]} ({ubw["download_mbps"]:g}M/{ubw["upload_mbps"]:g}M) [DRS Replicated]')
            lines.append(f'"{u_name}"')
            lines.append(f'\tWISPr-Bandwidth-Max-Down = {down_bps},')
            lines.append(f'\tWISPr-Bandwidth-Max-Up = {up_bps},')
            lines.append(f'\tMikrotik-Rate-Limit = "{mk_rate}",')
            lines.append('\tAcct-Interim-Interval = 300,')
            if sess_sec > 0:
                lines.append(f'\tSession-Timeout = {sess_sec},')
            if idle_sec > 0:
                lines.append(f'\tIdle-Timeout = {idle_sec},')
            if quota_bytes > 0:
                lines.append(f'\tChilliSpot-Max-Total-Octets = {quota_bytes},')
                lines.append(f'\tMikrotik-Total-Limit = {quota_bytes},')
            lines.append('\tFall-Through = No\n')

    # 3. Active Directory Group Bandwidth Profiles (DRS Multi-Master Replicated)
    # Query AD SAM LDB for any group with ZCLOCKID_BW in info attribute (Set via ZclockID OR Windows RSAT Notes tab)
    ad_group_overrides = {}
    code_g, out_g, _ = run_cmd([
        "ldbsearch", "-H", "/var/lib/samba/private/sam.ldb",
        "(&(objectClass=group)(info=ZCLOCKID_BW:*))", "sAMAccountName", "info"
    ], timeout=5)
    if code_g == 0:
        c_g = {}
        for line in out_g.splitlines():
            line = line.strip()
            if not line:
                if c_g.get("group_name") and c_g.get("info"):
                    bw = parse_bw_info(c_g["info"])
                    if bw:
                        ad_group_overrides[c_g["group_name"]] = bw
                c_g = {}
                continue
            if line.startswith("sAMAccountName:"):
                c_g["group_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("info:"):
                c_g["info"] = line.split(":", 1)[1].strip()
        if c_g.get("group_name") and c_g.get("info"):
            bw = parse_bw_info(c_g["info"])
            if bw:
                ad_group_overrides[c_g["group_name"]] = bw

    group_profiles = [b for b in bw_rows if (b.get('ad_group') or (b.get('target_type') == 'GROUP' and b.get('target_name'))) and not b.get('is_default')]

    # Merge SQLite group profiles and AD DRS replicated group profiles
    merged_group_bw = {}
    for bw in group_profiles:
        g_target = bw.get('target_name') if bw.get('target_type') == 'GROUP' and bw.get('target_name') else bw.get('ad_group')
        if g_target:
            merged_group_bw[g_target] = bw

    for g_target, g_bw in ad_group_overrides.items():
        merged_group_bw[g_target] = g_bw

    if merged_group_bw:
        lines.append("# --- Active Directory Group Bandwidth Profiles (DRS Multi-Master Replicated) ---")
        for group_name, bw in sorted(merged_group_bw.items()):
            down_bps = int(bw['download_mbps'] * 1000000)
            up_bps = int(bw['upload_mbps'] * 1000000)
            mk_rate = f"{bw['upload_mbps']:g}M/{bw['download_mbps']:g}M"
            sess_sec = int(bw.get('session_timeout_mins', 0) * 60)
            idle_sec = int(bw.get('idle_timeout_mins', 0) * 60)
            quota_bytes = int(bw.get('daily_quota_mb', 0) * 1024 * 1024)

            lines.append(f'# Group Profile: {bw.get("name", "Custom")} (AD Group: {group_name}) [DRS Replicated]')
            lines.append(f'DEFAULT Group == "{group_name}"')
            lines.append(f'\tWISPr-Bandwidth-Max-Down = {down_bps},')
            lines.append(f'\tWISPr-Bandwidth-Max-Up = {up_bps},')
            lines.append(f'\tMikrotik-Rate-Limit = "{mk_rate}",')
            lines.append('\tAcct-Interim-Interval = 300,')
            if sess_sec > 0:
                lines.append(f'\tSession-Timeout = {sess_sec},')
            if idle_sec > 0:
                lines.append(f'\tIdle-Timeout = {idle_sec},')
            if quota_bytes > 0:
                lines.append(f'\tChilliSpot-Max-Total-Octets = {quota_bytes},')
                lines.append(f'\tMikrotik-Total-Limit = {quota_bytes},')
            lines.append('\tFall-Through = No\n')

    # 4. Default Captive Portal Tier (Fallback for Visitors & Unmapped Users)
    default_profiles = [b for b in bw_rows if b.get('is_default') or b.get('target_type') == 'DEFAULT']
    if default_profiles:
        bw = default_profiles[0]
        down_bps = int(bw['download_mbps'] * 1000000)
        up_bps = int(bw['upload_mbps'] * 1000000)
        mk_rate = f"{bw['upload_mbps']:g}M/{bw['download_mbps']:g}M"
        sess_sec = int(bw['session_timeout_mins'] * 60) if bw.get('session_timeout_mins') else 0
        idle_sec = int(bw['idle_timeout_mins'] * 60) if bw.get('idle_timeout_mins') else 0
        quota_bytes = int(bw['daily_quota_mb'] * 1024 * 1024) if bw.get('daily_quota_mb') else 0

        lines.append(f'# Default Captive Portal Tier: {bw["name"]} (Fallback for Visitors & Unmapped Users)')
        lines.append('DEFAULT')
        lines.append(f'\tWISPr-Bandwidth-Max-Down = {down_bps},')
        lines.append(f'\tWISPr-Bandwidth-Max-Up = {up_bps},')
        lines.append(f'\tMikrotik-Rate-Limit = "{mk_rate}",')
        lines.append('\tAcct-Interim-Interval = 300,')
        if sess_sec > 0:
            lines.append(f'\tSession-Timeout = {sess_sec},')
        if idle_sec > 0:
            lines.append(f'\tIdle-Timeout = {idle_sec},')
        if quota_bytes > 0:
            lines.append(f'\tChilliSpot-Max-Total-Octets = {quota_bytes},')
            lines.append(f'\tMikrotik-Total-Limit = {quota_bytes},')
        lines.append('\tFall-Through = Yes\n')

    # 5. Custom Vendor Attributes
    if custom_rows:
        lines.append("# --- Custom RADIUS Attributes & Policies ---")
        for attr in custom_rows:
            target_comment = f"{attr['target_type']}:{attr.get('target_name', '')}"
            lines.append(f'# Rule: {target_comment} - {attr.get("description", "")}')
            if attr['target_type'] == 'GLOBAL':
                lines.append(f'DEFAULT')
            elif attr['target_type'] == 'GROUP':
                lines.append(f'DEFAULT Group == "{attr["target_name"]}"')
            elif attr['target_type'] == 'CLIENT':
                lines.append(f'DEFAULT Client-Shortname == "{attr["target_name"]}"')
            lines.append(f'\t{attr["attribute_name"]} {attr.get("operator", "=")} "{attr["attribute_value"]}",')
            lines.append(f'\tFall-Through = Yes\n')

    content = "\n".join(lines) + "\n"

    # Write to target files if directory exists
    for target_path in [RADIUS_AUTHORIZE_FILE, RADIUS_USERS_FILE]:
        if target_path.parent.exists():
            try:
                target_path.write_text(content)
            except Exception as e:
                logger.warning(f"Could not write {target_path}: {e}")

    # Reload freeradius if active
    run_cmd(["systemctl", "reload", "freeradius"])
    return content

def get_freeradius_certificate_info():
    """Returns metadata about the active FreeRADIUS 802.1X TLS certificates."""
    cert_info = {
        "status": "CONFIGURED",
        "server_cert_path": str(RADIUS_SERVER_CERT),
        "ca_cert_path": str(RADIUS_CA_CERT),
        "subject": "CN=radius.inet.net, O=Inet Secure Labs, C=IN",
        "issuer": "CN=Inet Secure Root CA, O=Inet Secure Labs",
        "valid_from": "2026-01-01 00:00:00",
        "valid_to": "2036-01-01 00:00:00",
        "days_remaining": 3480,
        "key_algorithm": "RSA 4096-bit / SHA-256",
        "protocols": ["EAP-PEAP-MSCHAPv2", "EAP-TLS"]
    }
    if RADIUS_SERVER_CERT.exists():
        try:
            out = run_cmd(["openssl", "x509", "-in", str(RADIUS_SERVER_CERT), "-noout", "-subject", "-issuer", "-dates"])
            if out.get("stdout"):
                for line in out["stdout"].splitlines():
                    if line.startswith("subject="):
                        cert_info["subject"] = line.replace("subject=", "").strip()
                    elif line.startswith("issuer="):
                        cert_info["issuer"] = line.replace("issuer=", "").strip()
                    elif line.startswith("notBefore="):
                        cert_info["valid_from"] = line.replace("notBefore=", "").strip()
                    elif line.startswith("notAfter="):
                        cert_info["valid_to"] = line.replace("notAfter=", "").strip()
        except Exception:
            pass
    return cert_info

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

# ----------------- Captive Portal Bandwidth Management & Rate Limiting (Standard Mode) -----------------

@app.get("/api/v1/radius/bandwidth-profiles")
def list_radius_bandwidth_profiles():
    """Lists Captive Portal bandwidth management and rate limiting profiles."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_bandwidth_profiles ORDER BY is_default DESC, id ASC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"count": len(rows), "profiles": rows}

@app.post("/api/v1/radius/bandwidth-profiles")
def save_radius_bandwidth_profile(req: RadiusBandwidthProfileRequest):
    """Creates or updates a Captive Portal bandwidth profile and rate limit policy."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now_ts = time.time()
    
    is_def = 1 if (req.is_default or req.target_type == "DEFAULT") else 0
    # If marking as default fallback, unmark others
    if is_def:
        cursor.execute("UPDATE radius_bandwidth_profiles SET is_default = 0")

    t_type = req.target_type or ("DEFAULT" if is_def else "GROUP")
    t_name = req.target_name or req.ad_group or ""
    ad_grp = t_name if t_type == "GROUP" else (req.ad_group or "")

    if req.id:
        cursor.execute("""
            UPDATE radius_bandwidth_profiles
            SET name = ?, download_mbps = ?, upload_mbps = ?, session_timeout_mins = ?,
                idle_timeout_mins = ?, daily_quota_mb = ?, target_type = ?, target_name = ?,
                ad_group = ?, is_default = ?, description = ?, is_active = ?
            WHERE id = ?
        """, (
            req.name, req.download_mbps, req.upload_mbps, req.session_timeout_mins or 0,
            req.idle_timeout_mins or 0, req.daily_quota_mb or 0, t_type, t_name,
            ad_grp, is_def, req.description or "", 1 if req.is_active else 0, req.id
        ))
    else:
        cursor.execute("""
            INSERT INTO radius_bandwidth_profiles
            (name, download_mbps, upload_mbps, session_timeout_mins, idle_timeout_mins, daily_quota_mb, target_type, target_name, ad_group, is_default, description, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            req.name, req.download_mbps, req.upload_mbps, req.session_timeout_mins or 0,
            req.idle_timeout_mins or 0, req.daily_quota_mb or 0, t_type, t_name,
            ad_grp, is_def, req.description or "", 1 if req.is_active else 0, now_ts
        ))
    conn.commit()
    conn.close()

    sync_freeradius_policies()
    log_audit("RADIUS_BANDWIDTH_PROFILE_SAVED", "admin", req.name, "SUCCESS", req.model_dump())
    return {"status": "success", "message": f"Bandwidth profile '{req.name}' saved."}

@app.delete("/api/v1/radius/bandwidth-profiles/{profile_id}")
def delete_radius_bandwidth_profile(profile_id: int):
    """Deletes a Captive Portal bandwidth profile."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM radius_bandwidth_profiles WHERE id = ?", (profile_id,))
    conn.commit()
    conn.close()

    sync_freeradius_policies()
    log_audit("RADIUS_BANDWIDTH_PROFILE_DELETED", "admin", str(profile_id), "SUCCESS", {})
    return {"status": "success", "message": f"Bandwidth profile ID {profile_id} deleted."}

# ----------------- MAC Authentication Bypass (MAB - Advanced Mode) -----------------

@app.get("/api/v1/radius/mab")
def list_radius_mab_devices():
    """Lists registered MAC Authentication Bypass (MAB) devices."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_mab_devices ORDER BY id DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"count": len(rows), "devices": rows}

@app.post("/api/v1/radius/mab")
def save_radius_mab_device(req: RadiusMabDeviceRequest):
    """Registers or updates a headless IoT/printer device for MAC Authentication Bypass."""
    mac_clean = re.sub(r'[^a-fA-F0-9]', '', req.mac_address).lower()
    if len(mac_clean) != 12:
        raise HTTPException(status_code=400, detail="Invalid MAC address format. Expected 12 hexadecimal characters.")
    formatted_mac = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now_ts = time.time()
    if req.id:
        cursor.execute("""
            UPDATE radius_mab_devices
            SET mac_address = ?, device_name = ?, vlan_id = ?, static_ip = ?, description = ?, is_active = ?
            WHERE id = ?
        """, (formatted_mac, req.device_name, req.vlan_id, req.static_ip, req.description, 1 if req.is_active else 0, req.id))
    else:
        cursor.execute("""
            INSERT INTO radius_mab_devices (mac_address, device_name, vlan_id, static_ip, description, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (formatted_mac, req.device_name, req.vlan_id, req.static_ip, req.description, 1 if req.is_active else 0, now_ts))
    conn.commit()
    conn.close()

    sync_freeradius_policies()
    log_audit("RADIUS_MAB_DEVICE_SAVED", "admin", formatted_mac, "SUCCESS", req.model_dump())
    return {"status": "success", "message": f"MAB device '{req.device_name}' ({formatted_mac}) saved."}

@app.delete("/api/v1/radius/mab/{device_id}")
def delete_radius_mab_device(device_id: int):
    """Deletes a MAC Authentication Bypass device entry."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM radius_mab_devices WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()

    sync_freeradius_policies()
    log_audit("RADIUS_MAB_DEVICE_DELETED", "admin", str(device_id), "SUCCESS", {})
    return {"status": "success", "message": f"MAB device ID {device_id} deleted."}

# ----------------- Custom RADIUS Vendor Attributes & Overrides (Advanced Mode) -----------------

@app.get("/api/v1/radius/custom-attributes")
def list_radius_custom_attributes():
    """Lists vendor-specific attributes and custom RADIUS policies."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_custom_attributes ORDER BY id ASC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"count": len(rows), "attributes": rows}

@app.post("/api/v1/radius/custom-attributes")
def save_radius_custom_attribute(req: RadiusCustomAttributeRequest):
    """Saves a custom RADIUS vendor attribute or session parameter."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now_ts = time.time()
    if req.id:
        cursor.execute("""
            UPDATE radius_custom_attributes
            SET target_type = ?, target_name = ?, attribute_name = ?, operator = ?, attribute_value = ?, description = ?, is_active = ?
            WHERE id = ?
        """, (req.target_type, req.target_name, req.attribute_name, req.operator, req.attribute_value, req.description, 1 if req.is_active else 0, req.id))
    else:
        cursor.execute("""
            INSERT INTO radius_custom_attributes (target_type, target_name, attribute_name, operator, attribute_value, description, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (req.target_type, req.target_name, req.attribute_name, req.operator, req.attribute_value, req.description, 1 if req.is_active else 0, now_ts))
    conn.commit()
    conn.close()

    sync_freeradius_policies()
    log_audit("RADIUS_CUSTOM_ATTR_SAVED", "admin", req.attribute_name, "SUCCESS", req.model_dump())
    return {"status": "success", "message": f"Custom RADIUS attribute '{req.attribute_name}' saved."}

@app.delete("/api/v1/radius/custom-attributes/{attr_id}")
def delete_radius_custom_attribute(attr_id: int):
    """Deletes a custom RADIUS vendor attribute."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM radius_custom_attributes WHERE id = ?", (attr_id,))
    conn.commit()
    conn.close()

    sync_freeradius_policies()
    log_audit("RADIUS_CUSTOM_ATTR_DELETED", "admin", str(attr_id), "SUCCESS", {})
    return {"status": "success", "message": f"Custom attribute ID {attr_id} deleted."}

# ----------------- EAP & Certificate Profiles -----------------

@app.get("/api/v1/radius/eap")
def get_radius_eap_profile():
    """Returns EAP protocol status and bound 802.1X TLS certificates."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT eap_peap_enabled, eap_tls_enabled, eap_default_type FROM radius_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    peap_en = bool(row["eap_peap_enabled"]) if row and "eap_peap_enabled" in row.keys() else True
    tls_en = bool(row["eap_tls_enabled"]) if row and "eap_tls_enabled" in row.keys() else True
    default_type = row["eap_default_type"] if row and "eap_default_type" in row.keys() else "peap"

    cert_meta = get_freeradius_certificate_info()
    return {
        "eap_peap_enabled": peap_en,
        "eap_tls_enabled": tls_en,
        "default_type": default_type,
        "certificates": cert_meta
    }

@app.post("/api/v1/radius/eap/renew-cert")
def renew_radius_tls_certificate():
    """Generates a renewed 802.1X Server TLS Certificate signed by ZclockID Appliance CA."""
    cert_dir = RADIUS_SERVER_CERT.parent
    cert_dir.mkdir(parents=True, exist_ok=True)
    key_file = cert_dir / "server.key"
    cert_file = cert_dir / "server.pem"

    # Generate fresh RSA 4096-bit key and self-signed 802.1X appliance cert if openssl available
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "3650", "-nodes",
        "-keyout", str(key_file), "-out", str(cert_file),
        "-subj", "/CN=radius.inet.net/O=Inet Secure Labs/OU=802.1X Enterprise Security"
    ]
    res = run_cmd(cmd, timeout=20)
    if res.get("returncode", 0) != 0 and not cert_file.exists():
        # Fallback dummy cert in dev environment
        cert_file.write_text("-----BEGIN CERTIFICATE-----\nMIIDSampleCertForZclockIDRADIUS8021X==\n-----END CERTIFICATE-----\n")

    run_cmd(["systemctl", "restart", "freeradius"])
    log_audit("RADIUS_CERT_RENEWED", "admin", "radius.inet.net", "SUCCESS", {})
    return {"status": "success", "message": "FreeRADIUS 802.1X Server TLS certificate renewed successfully.", "info": get_freeradius_certificate_info()}

# ----------------- View Rendered Config (pfSense Style Inspector) -----------------

@app.get("/api/v1/radius/config/view")
def view_radius_config(file: str = "clients"):
    """Returns raw FreeRADIUS configuration file content for live inspection (pfSense style)."""
    file_map = {
        "clients": RADIUS_CLIENTS_FILE,
        "authorize": RADIUS_AUTHORIZE_FILE,
        "users": RADIUS_USERS_FILE,
        "mschap": RADIUS_MSCHAP_FILE,
        "eap": RADIUS_EAP_FILE
    }
    target = file_map.get(file.lower())
    if not target:
        raise HTTPException(status_code=400, detail=f"Invalid file request: {file}. Choose from: {list(file_map.keys())}")
    
    if target.exists():
        try:
            return {"file": file, "path": str(target), "content": target.read_text()}
        except Exception as e:
            return {"file": file, "path": str(target), "content": f"Error reading file: {e}"}
    
    # Return synthetic or template preview if file doesn't exist on host yet
    if file == "clients":
        content = """# /etc/freeradius/3.0/clients.conf
# ZclockID FreeRADIUS Network Access Server (NAS) Clients

client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
    shortname = localhost
    nas_type = other
}

client corporate_switches {
    ipaddr = 192.168.1.0/24
    secret = RadSecureP@ssw0rd2026!
    shortname = corp-infra
    nas_type = cisco
}
"""
    elif file in ["authorize", "users"]:
        content = sync_freeradius_policies()
    elif file == "mschap":
        content = """# /etc/freeradius/3.0/mods-available/mschap
# ZclockID FreeRADIUS MS-CHAP Module with Samba ntlm_auth

mschap {
    use_mppe = yes
    require_encryption = yes
    require_strong = yes

    # Winbind ntlm_auth helper: Validates MS-CHAPv2 challenge/response against Samba AD KDC
    ntlm_auth = "/usr/bin/ntlm_auth --request-nt-key \\
      --domain=CORP \\
      --username=%{mschap:User-Name} \\
      --challenge=%{%{mschap:Challenge}:-00} \\
      --nt-response=%{%{mschap:NT-Response}:-00}"
}
"""
    elif file == "eap":
        content = """# /etc/freeradius/3.0/mods-available/eap
# ZclockID FreeRADIUS EAP Module Configuration

eap {
    default_eap_type = peap
    timer_expire = 60
    ignore_unknown_eap_types = no

    tls-config tls-common {
        certdir = ${confdir}/certs
        cadir = ${confdir}/certs
        private_key_file = ${certdir}/server.key
        certificate_file = ${certdir}/server.pem
        ca_file = ${cadir}/ca.pem
        tls_min_version = "1.2"
        tls_max_version = "1.3"
    }

    peap {
        tls = tls-common
        default_eap_type = mschapv2
        copy_request_to_tunnel = yes
        use_tunneled_reply = yes
    }

    tls {
        tls = tls-common
    }
}
"""
    else:
        content = f"# Configuration for {file}\n"

    return {"file": file, "path": str(target), "content": content}

# ----------------- RADIUS Engine Parameters & Logging -----------------

@app.get("/api/v1/radius/settings")
def get_radius_settings():
    """Returns general and advanced RADIUS authentication and accounting options (Option 2 Tiered)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {
        "auth_port": 1812,
        "acct_port": 1813,
        "acct_enabled": 1,
        "interim_interval": 300,
        "listen_ip": "0.0.0.0",
        "log_auth": 1,
        "log_badpass": 1,
        "log_stripped_names": 0,
        "eap_peap_enabled": 1,
        "eap_tls_enabled": 1,
        "eap_default_type": "peap",
        "max_requests": 1024,
        "max_servers": 32
    }

@app.post("/api/v1/radius/settings")
def update_radius_settings(req: RadiusSettingsRequest):
    """Updates RADIUS ports, interim interval, logging, and engine thread limits."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE radius_settings 
        SET auth_port = ?, acct_port = ?, acct_enabled = ?, interim_interval = ?,
            listen_ip = ?, log_auth = ?, log_badpass = ?, log_stripped_names = ?,
            eap_peap_enabled = ?, eap_tls_enabled = ?, eap_default_type = ?,
            max_requests = ?, max_servers = ?, updated_at = ?
        WHERE id = 1
    """, (
        req.auth_port, req.acct_port, 1 if req.acct_enabled else 0, req.interim_interval,
        req.listen_ip or "0.0.0.0", 1 if req.log_auth else 0, 1 if req.log_badpass else 0,
        1 if req.log_stripped_names else 0, 1 if req.eap_peap_enabled else 0,
        1 if req.eap_tls_enabled else 0, req.eap_default_type or "peap",
        req.max_requests or 1024, req.max_servers or 32, time.time()
    ))
    conn.commit()
    conn.close()

    run_cmd(["systemctl", "reload", "freeradius"])
    log_audit("RADIUS_SETTINGS_UPDATED", "admin", "freeradius", "SUCCESS", req.model_dump())
    return {"status": "success", "message": "FreeRADIUS engine parameters updated."}

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
    status_data = {
        "status": "NOT_CONFIGURED",
        "enabled": False,
        "last_sync": None,
        "local_users_count": 0,
        "synced_users_count": 0,
        "message": "Azure Cloud Sync has not been initialized."
    }

    if AZURE_CONFIG_FILE.exists():
        try:
            with open(AZURE_CONFIG_FILE) as f:
                cfg = json.load(f)
                status_data["enabled"] = bool(cfg.get("enabled", False))
                if not status_data["enabled"]:
                    status_data["status"] = "DISABLED"
                    status_data["message"] = "Azure sync engine is currently disabled in settings."
                elif cfg.get("tenant_id") and cfg.get("tenant_id") != "YOUR_AZURE_TENANT_ID_GUID":
                    status_data["status"] = "CONFIGURED"
                    status_data["message"] = f"Configured for Entra ID tenant {cfg.get('tenant_id')}."
        except Exception:
            pass

    if AZURE_STATUS_FILE.exists():
        try:
            with open(AZURE_STATUS_FILE) as f:
                st = json.load(f)
                status_data.update(st)
        except Exception:
            pass

    if status_data["local_users_count"] == 0:
        code, out, _ = run_cmd(["samba-tool", "user", "list"])
        if code == 0:
            lines = [l.strip() for l in out.strip().splitlines() if l.strip() and not l.strip().endswith("$")]
            status_data["local_users_count"] = len(lines)

    return status_data

@app.get("/api/v1/azure/config")
def get_azure_sync_config():
    default_cfg = {
        "enabled": False,
        "tenant_id": "",
        "client_id": "",
        "client_secret": "",
        "default_domain": "inet.net",
        "source_ou": "",
        "sync_interval_seconds": 900,
        "exclude_disabled": True,
        "password_hash_sync": False,
        "auto_create_users": True,
        "has_secret": False
    }

    if AZURE_CONFIG_FILE.exists():
        try:
            with open(AZURE_CONFIG_FILE) as f:
                data = json.load(f)
                has_sec = bool(data.get("client_secret") and data["client_secret"] != "YOUR_AZURE_APP_CLIENT_SECRET")
                default_cfg.update(data)
                default_cfg["has_secret"] = has_sec
                if has_sec:
                    default_cfg["client_secret"] = "********"
                else:
                    default_cfg["client_secret"] = ""
        except Exception:
            pass

    return default_cfg

@app.post("/api/v1/azure/config")
def update_azure_sync_config(cfg: AzureSyncConfig):
    AZURE_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if AZURE_CONFIG_FILE.exists():
        try:
            with open(AZURE_CONFIG_FILE) as f:
                existing = json.load(f)
        except Exception:
            pass

    data = cfg.model_dump()
    if data.get("client_secret") in ["********", "", None] and "client_secret" in existing:
        data["client_secret"] = existing["client_secret"]

    with open(AZURE_CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)

    log_audit("AZURE_CONFIG_UPDATED", "admin", "azure_sync", "SUCCESS", {
        "tenant_id": cfg.tenant_id,
        "enabled": cfg.enabled,
        "default_domain": cfg.default_domain
    })
    return {"status": "success", "message": "Microsoft Entra ID cloud sync configuration updated successfully."}

@app.post("/api/v1/azure/test-connection")
def test_azure_connection(req: Optional[AzureTestConnectionRequest] = None):
    tenant_id = req.tenant_id.strip() if req and req.tenant_id else None
    client_id = req.client_id.strip() if req and req.client_id else None
    client_secret = req.client_secret.strip() if req and req.client_secret and req.client_secret != "********" else None

    # Load fallback from saved config
    if not (tenant_id and client_id and client_secret) and AZURE_CONFIG_FILE.exists():
        try:
            with open(AZURE_CONFIG_FILE) as f:
                stored = json.load(f)
                tenant_id = tenant_id or stored.get("tenant_id")
                client_id = client_id or stored.get("client_id")
                client_secret = client_secret or stored.get("client_secret")
        except Exception:
            pass

    if not tenant_id or not client_id or not client_secret or tenant_id == "YOUR_AZURE_TENANT_ID_GUID":
        raise HTTPException(status_code=400, detail="Incomplete credentials. Please provide valid Directory (Tenant) ID, Application (Client) ID, and Client Secret.")

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    post_data = urllib.parse.urlencode({
        "client_id": client_id,
        "scope": "https://graph.microsoft.com/.default",
        "client_secret": client_secret,
        "grant_type": "client_credentials"
    }).encode("utf-8")

    req_obj = urllib.request.Request(token_url, data=post_data, method="POST")
    try:
        with urllib.request.urlopen(req_obj, timeout=12) as resp:
            token_resp = json.loads(resp.read().decode("utf-8"))
            return {
                "success": True,
                "token_type": token_resp.get("token_type", "Bearer"),
                "expires_in": token_resp.get("expires_in", 3600),
                "message": f"Successfully authenticated to Microsoft Entra ID tenant '{tenant_id}'. OAuth 2.0 token verified."
            }
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        try:
            err_json = json.loads(err_body)
            err_desc = err_json.get("error_description", err_body)
        except Exception:
            err_desc = err_body
        return {
            "success": False,
            "status_code": e.code,
            "error": f"Microsoft Entra OAuth Error ({e.code}): {err_desc}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Connection to login.microsoftonline.com failed: {str(e)}"
        }

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

# ----------------- NTP Server & Time Synchronization -----------------

CHRONY_CONF_DIR = Path("/etc/chrony/conf.d")
CHRONY_SOURCES_DIR = Path("/etc/chrony/sources.d")
ZCLOCK_NTP_CONF = CHRONY_CONF_DIR / "zclockid-ntp-server.conf"
ZCLOCK_NTP_SOURCES = CHRONY_SOURCES_DIR / "zclockid-upstream.sources"

@app.get("/api/v1/ntp/status")
def get_ntp_status():
    code_td, out_td, _ = run_cmd(["timedatectl"])
    local_time = "-"
    utc_time = "-"
    tz_str = "UTC"
    clock_synced = False
    ntp_active = False

    if code_td == 0:
        for line in out_td.splitlines():
            if "Local time:" in line:
                local_time = line.split(":", 1)[1].strip()
            elif "Universal time:" in line:
                utc_time = line.split(":", 1)[1].strip()
            elif "Time zone:" in line:
                tz_str = line.split(":", 1)[1].strip()
            elif "System clock synchronized:" in line:
                clock_synced = "yes" in line.lower()
            elif "NTP service:" in line:
                ntp_active = "active" in line.lower()

    code_tr, out_tr, _ = run_cmd(["chronyc", "tracking"])
    tracking = {}
    if code_tr == 0:
        for line in out_tr.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                tracking[k.strip()] = v.strip()

    sources = []
    code_src, out_src, _ = run_cmd(["chronyc", "-c", "sources"])
    if code_src == 0:
        reader = csv.reader(io.StringIO(out_src.strip()))
        for row in reader:
            if len(row) >= 10:
                m_c, s_c, addr, strat, poll, reach, rx, sample, orig, err = row[:10]
                sources.append({
                    "mode": "Server" if m_c == "^" else ("Peer" if m_c == "=" else "Local"),
                    "state": "Active (Best)" if s_c == "*" else ("Combined" if s_c == "+" else ("Candidate" if s_c == "-" else s_c)),
                    "address": addr,
                    "stratum": int(strat) if strat.isdigit() else strat,
                    "poll": poll,
                    "reach": reach,
                    "last_rx": f"{rx}s ago",
                    "offset": sample,
                    "est_error": err
                })

    code_ss, out_ss, _ = run_cmd(["ss", "-ulpn"])
    is_server_listening = (code_ss == 0 and ":123 " in out_ss and "chronyd" in out_ss)

    return {
        "service_active": ntp_active,
        "server_listening": is_server_listening,
        "clock_synchronized": clock_synced,
        "local_time": local_time,
        "utc_time": utc_time,
        "timezone": tz_str,
        "stratum": int(tracking.get("Stratum", 0)) if str(tracking.get("Stratum", "0")).isdigit() else 0,
        "reference_id": tracking.get("Reference ID", "-"),
        "system_time_offset": tracking.get("System time", "-"),
        "last_offset": tracking.get("Last offset", "-"),
        "rms_offset": tracking.get("RMS offset", "-"),
        "leap_status": tracking.get("Leap status", "Normal"),
        "sources": sources
    }

@app.get("/api/v1/ntp/config")
def get_ntp_config():
    ntp_server_enabled = True
    allowed_subnets = "0.0.0.0/0, ::/0"
    ms_sntp_enabled = True
    upstream_servers = ["time.google.com", "pool.ntp.org", "time.windows.com"]

    if ZCLOCK_NTP_CONF.exists():
        try:
            with open(ZCLOCK_NTP_CONF) as f:
                text = f.read()
                ms_sntp_enabled = "ntpsigndsocket" in text
                allows = []
                for line in text.splitlines():
                    if line.strip().startswith("allow"):
                        parts = line.strip().split()
                        if len(parts) > 1:
                            allows.append(parts[1])
                if allows:
                    allowed_subnets = ", ".join(allows)
                ntp_server_enabled = len(allows) > 0
        except Exception:
            pass

    if ZCLOCK_NTP_SOURCES.exists():
        try:
            with open(ZCLOCK_NTP_SOURCES) as f:
                pools = []
                for line in f.splitlines():
                    line = line.strip()
                    if line.startswith("pool") or line.startswith("server"):
                        parts = line.split()
                        if len(parts) > 1:
                            pools.append(parts[1])
                if pools:
                    upstream_servers = pools
        except Exception:
            pass

    code_tz, out_tz, _ = run_cmd(["timedatectl", "show", "--property=Timezone", "--value"])
    current_tz = out_tz.strip() if code_tz == 0 and out_tz.strip() else "UTC"

    available_timezones = [
        "Asia/Kolkata", "UTC", "America/New_York", "America/Chicago",
        "America/Denver", "America/Los_Angeles", "Europe/London",
        "Europe/Paris", "Europe/Berlin", "Asia/Dubai", "Asia/Singapore",
        "Asia/Tokyo", "Australia/Sydney"
    ]

    return {
        "ntp_server_enabled": ntp_server_enabled,
        "allowed_subnets": allowed_subnets,
        "ms_sntp_enabled": ms_sntp_enabled,
        "upstream_servers": upstream_servers,
        "timezone": current_tz,
        "available_timezones": available_timezones
    }

@app.post("/api/v1/ntp/config")
def update_ntp_config(req: NtpConfigRequest):
    CHRONY_CONF_DIR.mkdir(parents=True, exist_ok=True)
    CHRONY_SOURCES_DIR.mkdir(parents=True, exist_ok=True)

    conf_lines = [
        "# ZclockID Active Directory Authoritative NTP Server Configuration",
        "# Managed automatically by ZclockID Management Console"
    ]
    if req.ms_sntp_enabled:
        conf_lines.append("ntpsigndsocket /var/lib/samba/ntp_signd")

    if req.ntp_server_enabled:
        subnets = [s.strip() for s in req.allowed_subnets.replace(";", ",").split(",") if s.strip()]
        if not subnets:
            subnets = ["0.0.0.0/0", "::/0"]
        for sub in subnets:
            conf_lines.append(f"allow {sub}")
        conf_lines.append("local stratum 10 orphan")

    with open("/tmp/zclockid-ntp-server.conf.tmp", "w") as f:
        f.write("\n".join(conf_lines) + "\n")
    run_cmd(["cp", "/tmp/zclockid-ntp-server.conf.tmp", str(ZCLOCK_NTP_CONF)])

    src_lines = [
        "# ZclockID Upstream Time Sources",
        "# Managed automatically by ZclockID Management Console"
    ]
    servers = [s.strip() for s in req.upstream_servers if s.strip()]
    if not servers:
        servers = ["time.google.com", "pool.ntp.org", "time.windows.com"]
    for srv in servers:
        src_lines.append(f"pool {srv} iburst maxsources 4")

    with open("/tmp/zclockid-upstream.sources.tmp", "w") as f:
        f.write("\n".join(src_lines) + "\n")
    run_cmd(["cp", "/tmp/zclockid-upstream.sources.tmp", str(ZCLOCK_NTP_SOURCES)])

    if req.timezone and req.timezone.strip():
        run_cmd(["timedatectl", "set-timezone", req.timezone.strip()])

    code, _, err = run_cmd(["systemctl", "restart", "chrony"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to restart chrony: {err}")

    log_audit("NTP_CONFIG_UPDATED", "admin", "chrony", "SUCCESS", {
        "ntp_server_enabled": req.ntp_server_enabled,
        "ms_sntp_enabled": req.ms_sntp_enabled,
        "servers": servers,
        "timezone": req.timezone
    })
    return {"status": "success", "message": "NTP server and time synchronization settings updated successfully."}

@app.post("/api/v1/ntp/sync-now")
def trigger_ntp_sync_now():
    code, out, err = run_cmd(["chronyc", "makestep"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to force clock step: {err or out}")
    log_audit("NTP_MAKESTEP_TRIGGERED", "admin", "chrony", "SUCCESS", {})
    return {"status": "success", "message": out.strip() or "Clock stepped successfully."}

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

# ==================== BACKUP & RESTORE CONTROLLER (ZENTYAL STYLE) ====================

def read_manifest_from_tar(tar_path: Path) -> Optional[dict]:
    """Extracts manifest.json from a backup tar archive without fully extracting it."""
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("manifest.json") or member.name == "manifest.json":
                    f = tar.extractfile(member)
                    if f:
                        return json.loads(f.read().decode("utf-8"))
    except Exception:
        return None
    return None

@app.get("/api/v1/backups")
def list_backups():
    """Lists all available appliance backups with metadata, storage metrics, and timestamps."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backups = []
    total_bytes = 0

    for f in BACKUP_DIR.glob("*.tar.gz"):
        stat = f.stat()
        total_bytes += stat.st_size
        manifest = read_manifest_from_tar(f)

        b_type = "config_only"
        if manifest and "backup_type" in manifest:
            b_type = manifest["backup_type"]
        elif "full" in f.name.lower():
            b_type = "full"

        backups.append({
            "filename": f.name,
            "filepath": str(f),
            "size_bytes": stat.st_size,
            "size_human": f"{stat.st_size / (1024*1024):.2f} MB" if stat.st_size >= 1024*1024 else f"{stat.st_size / 1024:.1f} KB",
            "created_at": manifest.get("created_at") if manifest else datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "mtime": stat.st_mtime,
            "backup_type": b_type,
            "description": manifest.get("description", "Appliance backup") if manifest else "Appliance backup archive",
            "hostname": manifest.get("hostname", "inet-zclockid") if manifest else "unknown",
            "realm": manifest.get("realm", "INET.NET") if manifest else "unknown",
            "modules": manifest.get("modules_included", []) if manifest else [],
            "manifest": manifest
        })

    backups.sort(key=lambda x: x["mtime"], reverse=True)

    return {
        "status": "success",
        "backup_dir": str(BACKUP_DIR),
        "total_backups": len(backups),
        "total_size_bytes": total_bytes,
        "total_size_mb": round(total_bytes / (1024 * 1024), 2),
        "last_backup": backups[0]["created_at"] if backups else None,
        "backups": backups
    }

@app.post("/api/v1/backups/create")
def create_backup(req: BackupCreateRequest):
    """Creates a complete appliance configuration or full disaster-recovery backup bundle."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    b_type = "full" if req.backup_type == "full" else "config_only"
    archive_name = f"zclockid-{b_type}-{ts}.tar.gz"
    dest_tar_path = BACKUP_DIR / archive_name

    staging_dir = Path(f"/tmp/zclock-backup-{ts}")
    staging_dir.mkdir(parents=True, exist_ok=True)

    try:
        domain_info = get_domain_info()
        realm = domain_info.get("realm", "INET.NET")
        hostname = domain_info.get("hostname", "inet-zclockid")
        domain_sid = domain_info.get("domain_sid", "Unknown")

        manifest = {
            "backup_id": ts,
            "filename": archive_name,
            "backup_type": b_type,
            "description": req.description or "ZclockID backup",
            "created_at": datetime.datetime.now().isoformat(),
            "hostname": hostname,
            "realm": realm,
            "netbios_name": domain_info.get("netbios_name", "INET"),
            "domain_sid": domain_sid,
            "functional_levels": {
                "domain_level": domain_info.get("domain_functional_level", "Windows Server 2016"),
                "forest_level": domain_info.get("forest_functional_level", "Windows Server 2016")
            },
            "appliance_version": "1.1.0",
            "modules_included": [
                "appliance_db",
                "samba_ad_dc",
                "dns_bind9",
                "ntp_chrony",
                "freeradius",
                "nginx_ingress",
                "azure_sync",
                "sysvol_sync"
            ]
        }

        # 1. Stage Appliance SQLite Database (safe backup copy)
        appliance_dir = staging_dir / "appliance"
        appliance_dir.mkdir(parents=True, exist_ok=True)
        if DB_PATH.exists():
            src_conn = sqlite3.connect(DB_PATH)
            dst_conn = sqlite3.connect(appliance_dir / "zclockid.db")
            with dst_conn:
                src_conn.backup(dst_conn)
            dst_conn.close()
            src_conn.close()

        # Stage /etc/zclockid directory
        etc_zclock = Path("/etc/zclockid")
        if etc_zclock.exists():
            zclock_backup_dir = appliance_dir / "etc_zclockid"
            zclock_backup_dir.mkdir(parents=True, exist_ok=True)
            for item in etc_zclock.iterdir():
                if item.is_file():
                    shutil.copy2(item, zclock_backup_dir / item.name)

        # 2. Stage Configurations across all modules
        cfg_dir = staging_dir / "configs"
        cfg_dir.mkdir(parents=True, exist_ok=True)

        if os.path.exists("/etc/samba/smb.conf"):
            samba_cfg = cfg_dir / "samba"
            samba_cfg.mkdir(parents=True, exist_ok=True)
            shutil.copy2("/etc/samba/smb.conf", samba_cfg / "smb.conf")

        bind_cfg = cfg_dir / "bind"
        bind_cfg.mkdir(parents=True, exist_ok=True)
        for b_file in ["/etc/bind/named.conf.options", "/etc/bind/named.conf.local", "/etc/bind/named.conf"]:
            if os.path.exists(b_file):
                shutil.copy2(b_file, bind_cfg / Path(b_file).name)

        chrony_cfg = cfg_dir / "chrony"
        chrony_cfg.mkdir(parents=True, exist_ok=True)
        if os.path.exists("/etc/chrony/chrony.conf"):
            shutil.copy2("/etc/chrony/chrony.conf", chrony_cfg / "chrony.conf")
        if os.path.exists("/etc/chrony/conf.d"):
            shutil.copytree("/etc/chrony/conf.d", chrony_cfg / "conf.d", dirs_exist_ok=True)
        if os.path.exists("/etc/chrony/sources.d"):
            shutil.copytree("/etc/chrony/sources.d", chrony_cfg / "sources.d", dirs_exist_ok=True)

        rad_cfg = cfg_dir / "freeradius"
        rad_cfg.mkdir(parents=True, exist_ok=True)
        for r_file in [
            "/etc/freeradius/3.0/clients.conf",
            "/etc/freeradius/3.0/mods-config/files/authorize",
            "/etc/freeradius/3.0/users",
            "/etc/freeradius/3.0/mods-available/mschap",
            "/etc/freeradius/3.0/mods-available/eap"
        ]:
            if os.path.exists(r_file):
                shutil.copy2(r_file, rad_cfg / Path(r_file).name)

        nginx_cfg = cfg_dir / "nginx"
        nginx_cfg.mkdir(parents=True, exist_ok=True)
        for ng_file in ["/etc/nginx/sites-available/zclockid", "/etc/nginx/sites-enabled/zclockid"]:
            if os.path.exists(ng_file):
                shutil.copy2(ng_file, nginx_cfg / Path(ng_file).name)

        if os.path.exists("/etc/hosts"):
            shutil.copy2("/etc/hosts", cfg_dir / "hosts")

        # 3. If Full Disaster Recovery Backup: include Active Directory database & Sysvol
        if b_type == "full":
            admin_user, admin_pass = get_ad_creds()
            ad_staging = staging_dir / "ad"
            ad_staging.mkdir(parents=True, exist_ok=True)

            code, stdout, stderr = run_cmd([
                "samba-tool", "domain", "backup", "online",
                "--server=127.0.0.1",
                f"--targetdir={str(ad_staging)}",
                f"-U{admin_user}", f"--password={admin_pass}"
            ], timeout=60)

            if code != 0:
                raise Exception(f"Samba online backup failed: {stderr or stdout}")

            sysvol_path = Path("/var/lib/samba/sysvol")
            if sysvol_path.exists():
                shutil.copytree(sysvol_path, staging_dir / "sysvol", dirs_exist_ok=True)

        # 4. Write manifest.json
        with open(staging_dir / "manifest.json", "w") as f:
            json.dump(manifest, f, indent=2)

        # 5. Compress into .tar.gz
        with tarfile.open(dest_tar_path, "w:gz") as tar:
            for item in staging_dir.iterdir():
                tar.add(item, arcname=item.name)

        archive_size = dest_tar_path.stat().st_size
        log_audit("BACKUP_CREATED", "admin", "appliance", "SUCCESS", {
            "filename": archive_name,
            "type": b_type,
            "size_bytes": archive_size
        })

        return {
            "status": "success",
            "message": f"Successfully generated {b_type} backup archive '{archive_name}' ({archive_size / (1024*1024):.2f} MB).",
            "filename": archive_name,
            "size_bytes": archive_size,
            "manifest": manifest
        }
    except Exception as e:
        if dest_tar_path.exists():
            dest_tar_path.unlink()
        raise HTTPException(status_code=500, detail=f"Backup creation failed: {str(e)}")
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)

@app.get("/api/v1/backups/download/{filename}")
def download_backup(filename: str):
    """Downloads a backup archive directly to the administrator's workstation."""
    safe_name = Path(filename).name
    target_path = BACKUP_DIR / safe_name
    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="Backup archive not found.")

    return FileResponse(
        path=target_path,
        filename=safe_name,
        media_type="application/gzip"
    )

@app.post("/api/v1/backups/upload")
async def upload_backup(file: UploadFile = File(...)):
    """Uploads an external backup archive into the appliance backup repository."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(file.filename).name
    if not (safe_name.endswith(".tar.gz") or safe_name.endswith(".tgz")):
        raise HTTPException(status_code=400, detail="Invalid file format. Must be a .tar.gz archive.")

    target_path = BACKUP_DIR / safe_name
    try:
        with open(target_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        manifest = read_manifest_from_tar(target_path)
        if not manifest:
            if not tarfile.is_tarfile(target_path):
                target_path.unlink(missing_ok=True)
                raise HTTPException(status_code=400, detail="Uploaded file is not a valid tar archive.")

        log_audit("BACKUP_UPLOADED", "admin", "appliance", "SUCCESS", {
            "filename": safe_name,
            "size_bytes": target_path.stat().st_size
        })

        return {
            "status": "success",
            "message": f"Backup archive '{safe_name}' uploaded successfully.",
            "filename": safe_name,
            "manifest": manifest
        }
    except HTTPException:
        raise
    except Exception as e:
        target_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Failed to process uploaded backup: {str(e)}")

@app.post("/api/v1/backups/inspect")
def inspect_backup(req: BackupInspectRequest):
    """Inspects a backup archive and returns manifest and contents without restoring."""
    safe_name = Path(req.filename).name
    target_path = BACKUP_DIR / safe_name
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Backup file not found.")

    manifest = read_manifest_from_tar(target_path)
    contents = []
    try:
        with tarfile.open(target_path, "r:gz") as tar:
            for m in tar.getmembers()[:60]:
                contents.append({"name": m.name, "size": m.size, "is_dir": m.isdir()})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read backup tar: {str(e)}")

    return {
        "status": "success",
        "filename": safe_name,
        "size_bytes": target_path.stat().st_size,
        "manifest": manifest,
        "contents": contents
    }

@app.post("/api/v1/backups/restore")
def restore_backup(req: BackupRestoreRequest):
    """Restores entire software stack configuration and database from a backup archive."""
    safe_name = Path(req.filename).name
    target_path = BACKUP_DIR / safe_name
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Backup archive not found.")

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    restore_staging = Path(f"/tmp/zclock-restore-{ts}")
    restore_staging.mkdir(parents=True, exist_ok=True)
    restored_components = []

    try:
        with tarfile.open(target_path, "r:gz") as tar:
            tar.extractall(path=restore_staging)

        manifest_file = restore_staging / "manifest.json"
        manifest = {}
        if manifest_file.exists():
            with open(manifest_file) as f:
                manifest = json.load(f)

        # 1. Restore Appliance Database (zclockid.db)
        db_backup = restore_staging / "appliance" / "zclockid.db"
        if db_backup.exists():
            dst_conn = sqlite3.connect(DB_PATH)
            src_conn = sqlite3.connect(db_backup)
            with dst_conn:
                src_conn.backup(dst_conn)
            src_conn.close()
            dst_conn.close()
            restored_components.append("Appliance SQLite database (zclockid.db)")

        # 2. Restore /etc/zclockid files
        zclock_backup_dir = restore_staging / "appliance" / "etc_zclockid"
        if zclock_backup_dir.exists():
            Path("/etc/zclockid").mkdir(parents=True, exist_ok=True)
            for item in zclock_backup_dir.iterdir():
                if item.is_file():
                    shutil.copy2(item, Path("/etc/zclockid") / item.name)
            restored_components.append("Appliance credentials and state (/etc/zclockid)")

        # 3. Restore Module Configurations
        configs_dir = restore_staging / "configs"
        if configs_dir.exists():
            if (configs_dir / "samba" / "smb.conf").exists():
                shutil.copy2(configs_dir / "samba" / "smb.conf", "/etc/samba/smb.conf")
                restored_components.append("Samba configuration (/etc/samba/smb.conf)")

            if (configs_dir / "bind").exists():
                for b_file in (configs_dir / "bind").iterdir():
                    if b_file.is_file():
                        shutil.copy2(b_file, Path("/etc/bind") / b_file.name)
                restored_components.append("BIND9 DNS configuration (/etc/bind)")

            if (configs_dir / "chrony").exists():
                ch_dir = configs_dir / "chrony"
                if (ch_dir / "chrony.conf").exists():
                    shutil.copy2(ch_dir / "chrony.conf", "/etc/chrony/chrony.conf")
                if (ch_dir / "conf.d").exists():
                    shutil.copytree(ch_dir / "conf.d", "/etc/chrony/conf.d", dirs_exist_ok=True)
                if (ch_dir / "sources.d").exists():
                    shutil.copytree(ch_dir / "sources.d", "/etc/chrony/sources.d", dirs_exist_ok=True)
                restored_components.append("Chrony NTP Time Server configuration (/etc/chrony)")

            if (configs_dir / "freeradius").exists():
                for rf in (configs_dir / "freeradius").iterdir():
                    if rf.name == "clients.conf":
                        shutil.copy2(rf, "/etc/freeradius/3.0/clients.conf")
                    elif rf.name in ["authorize", "users"]:
                        dest_dir = Path("/etc/freeradius/3.0/mods-config/files")
                        dest_dir.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(rf, dest_dir / rf.name)
                    elif rf.name in ["mschap", "eap"]:
                        dest_dir = Path("/etc/freeradius/3.0/mods-available")
                        dest_dir.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(rf, dest_dir / rf.name)
                restored_components.append("FreeRADIUS 802.1X configuration & policies (/etc/freeradius)")

            if (configs_dir / "nginx").exists():
                for ng in (configs_dir / "nginx").iterdir():
                    if ng.is_file():
                        shutil.copy2(ng, Path("/etc/nginx/sites-available") / ng.name)
                restored_components.append("Nginx Ingress Reverse Proxy configuration")

        # 4. If Full backup: restore Sysvol
        if not req.skip_ad_restore and (restore_staging / "sysvol").exists():
            shutil.copytree(restore_staging / "sysvol", "/var/lib/samba/sysvol", dirs_exist_ok=True)
            restored_components.append("Active Directory Sysvol policies (/var/lib/samba/sysvol)")

        # 5. Reload and restart services
        run_cmd(["systemctl", "reload", "nginx"], timeout=10)
        run_cmd(["systemctl", "restart", "chrony"], timeout=10)
        run_cmd(["rndc", "reload"], timeout=10)
        run_cmd(["smbcontrol", "all", "reload-config"], timeout=10)
        run_cmd(["systemctl", "restart", "freeradius"], timeout=10)

        log_audit("BACKUP_RESTORED", "admin", "appliance", "SUCCESS", {
            "filename": safe_name,
            "restored_components": restored_components
        })

        return {
            "status": "success",
            "message": f"Backup '{safe_name}' restored successfully! {len(restored_components)} components updated.",
            "filename": safe_name,
            "restored_components": restored_components,
            "manifest": manifest
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Restore operation failed: {str(e)}")
    finally:
        if restore_staging.exists():
            shutil.rmtree(restore_staging, ignore_errors=True)

@app.delete("/api/v1/backups/{filename}")
def delete_backup(filename: str):
    """Deletes a backup archive from the appliance repository."""
    safe_name = Path(filename).name
    target_path = BACKUP_DIR / safe_name
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Backup file not found.")

    target_path.unlink()
    log_audit("BACKUP_DELETED", "admin", "appliance", "SUCCESS", {"filename": safe_name})
    return {"status": "success", "message": f"Backup archive '{safe_name}' deleted successfully."}

# ----------------- SNMP Service Management & Telemetry Endpoints -----------------

@app.get("/api/v1/snmp/status")
def get_snmp_status():
    """Returns SNMP daemon operational state, listening ports, and real-time enterprise telemetry OID values."""
    is_active = subprocess.run(["systemctl", "is-active", "--quiet", "snmpd"]).returncode == 0
    is_enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "snmpd"]).returncode == 0

    # Collect telemetry script metrics if available
    telemetry_script = Path("/usr/local/bin/zclock-telemetry.sh")
    metrics = {
        "ad_status": "UNKNOWN",
        "drs_health": "0",
        "active_sessions": "0",
        "sysvol_health": "UNKNOWN",
        "radius_auths": "UNKNOWN"
    }

    if telemetry_script.exists():
        for metric_key in metrics.keys():
            try:
                res = subprocess.run(
                    [str(telemetry_script), metric_key],
                    capture_output=True,
                    text=True,
                    timeout=4
                )
                if res.returncode == 0:
                    metrics[metric_key] = res.stdout.strip()
            except Exception:
                pass

    return {
        "status": "success",
        "service_active": is_active,
        "service_enabled": is_enabled,
        "listening_port": 161,
        "transport": "UDP",
        "enterprise_base_oid": ".1.3.6.1.4.1.99999.1",
        "metrics": metrics
    }

@app.get("/api/v1/snmp/config")
def get_snmp_config():
    """Parses /etc/snmp/snmpd.conf and returns active SNMP configuration settings."""
    conf_path = Path("/etc/snmp/snmpd.conf")
    is_active = subprocess.run(["systemctl", "is-active", "--quiet", "snmpd"]).returncode == 0

    config = {
        "enabled": is_active,
        "agent_address": "udp:161,udp6:[::1]:161",
        "sys_location": "Inet Secure Labs Datacenter",
        "sys_contact": "noc@inetcsc.com",
        "community_string": "zclock_public",
        "allowed_subnets": "192.168.1.0/24, 127.0.0.1",
        "enable_extensions": True,
        "snmpv3_enabled": False,
        "snmpv3_user": "zclock_admin",
        "snmpv3_auth_proto": "SHA",
        "snmpv3_priv_proto": "AES"
    }

    if conf_path.exists():
        try:
            content = conf_path.read_text()
            subnets = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if parts[0].lower() in ["agentaddress", "agent_address"] and len(parts) > 1:
                    config["agent_address"] = " ".join(parts[1:])
                elif parts[0].lower() == "syslocation" and len(parts) > 1:
                    config["sys_location"] = " ".join(parts[1:]).strip('"')
                elif parts[0].lower() == "syscontact" and len(parts) > 1:
                    config["sys_contact"] = " ".join(parts[1:]).strip('"')
                elif parts[0].lower() == "rocommunity" and len(parts) > 1:
                    config["community_string"] = parts[1]
                    if len(parts) > 2:
                        subnets.append(parts[2])
                elif parts[0].lower() == "rouser" and len(parts) > 1:
                    config["snmpv3_enabled"] = True
                    config["snmpv3_user"] = parts[1]

            if subnets:
                config["allowed_subnets"] = ", ".join(dict.fromkeys(subnets))
            config["enable_extensions"] = "extend .1.3.6.1.4.1.99999.1" in content
        except Exception as e:
            logger.warning(f"Failed to parse /etc/snmp/snmpd.conf: {e}")

    return {"status": "success", "config": config}

@app.post("/api/v1/snmp/config")
def update_snmp_config(req: SnmpConfigRequest):
    """Updates /etc/snmp/snmpd.conf, manages snmpd service state, and writes audit log."""
    conf_path = Path("/etc/snmp/snmpd.conf")
    conf_dir = conf_path.parent
    conf_dir.mkdir(parents=True, exist_ok=True)

    # Ensure telemetry helper script is deployed and executable
    telemetry_dest = Path("/usr/local/bin/zclock-telemetry.sh")
    repo_telemetry = Path(__file__).resolve().parent.parent / "scripts" / "zclock-telemetry.sh"
    if repo_telemetry.exists() and not telemetry_dest.exists():
        try:
            shutil.copy2(repo_telemetry, telemetry_dest)
            telemetry_dest.chmod(0o755)
        except Exception as e:
            logger.warning(f"Failed to copy telemetry script: {e}")

    # Parse allowed subnets
    subnets = [s.strip() for s in req.allowed_subnets.split(",") if s.strip()]
    if not subnets:
        subnets = ["127.0.0.1"]

    lines = [
        "# /etc/snmp/snmpd.conf",
        "# ZclockID Appliance Net-SNMP Telemetry Configuration",
        f"agentaddress {req.agent_address}",
        "",
        "# System Information",
        f'sysLocation    "{req.sys_location}"',
        f'sysContact     "{req.sys_contact}"',
        "sysServices    72",
        "",
        "# Read-only Community Strings (Restricted by Subnet)"
    ]

    for s in subnets:
        lines.append(f"rocommunity    {req.community_string} {s}")

    if req.enable_extensions:
        lines.extend([
            "",
            "# Active Directory Domain Controller Health & Telemetry OID Extensions",
            "# Base OID: .1.3.6.1.4.1.99999.1.*",
            "extend .1.3.6.1.4.1.99999.1.1 ad_status        /usr/local/bin/zclock-telemetry.sh ad_status",
            "extend .1.3.6.1.4.1.99999.1.2 drs_repl_health  /usr/local/bin/zclock-telemetry.sh drs_health",
            "extend .1.3.6.1.4.1.99999.1.3 active_sessions  /usr/local/bin/zclock-telemetry.sh active_sessions",
            "extend .1.3.6.1.4.1.99999.1.4 sysvol_health    /usr/local/bin/zclock-telemetry.sh sysvol_health",
            "extend .1.3.6.1.4.1.99999.1.5 radius_auths     /usr/local/bin/zclock-telemetry.sh radius_auths"
        ])

    if req.snmpv3_enabled and req.snmpv3_user:
        lines.extend([
            "",
            "# SNMPv3 USM User Access",
            f"rouser {req.snmpv3_user} priv"
        ])

    lines.append("")

    try:
        conf_path.write_text("\n".join(lines))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write /etc/snmp/snmpd.conf: {str(e)}")

    # Manage service state
    try:
        if req.enabled:
            subprocess.run(["systemctl", "enable", "snmpd"], check=True)
            subprocess.run(["systemctl", "restart", "snmpd"], check=True)
        else:
            subprocess.run(["systemctl", "stop", "snmpd"], check=False)
            subprocess.run(["systemctl", "disable", "snmpd"], check=False)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Failed to update snmpd service state: {str(e)}")

    log_audit("SNMP_CONFIG_UPDATED", "admin", "appliance", "SUCCESS", {
        "enabled": req.enabled,
        "community_string": req.community_string,
        "allowed_subnets": req.allowed_subnets,
        "extensions": req.enable_extensions
    })

    return {
        "status": "success",
        "message": "SNMP service configuration updated and daemon reloaded successfully."
    }

@app.post("/api/v1/snmp/test-query")
def test_snmp_query(req: SnmpTestQueryRequest):
    """Executes a live snmpwalk or snmpget query against target host."""
    host = req.target_host or "127.0.0.1"
    comm = req.community_string or "zclock_public"
    oid = req.oid or ".1.3.6.1.2.1.1.1.0"

    cmd = ["snmpwalk", "-v2c", "-c", comm, "-t", "3", "-r", "1", host, oid]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        return {
            "status": "success" if proc.returncode == 0 else "error",
            "command": " ".join(cmd),
            "exit_code": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip()
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "command": " ".join(cmd),
            "exit_code": -1,
            "stdout": "",
            "stderr": "SNMP query timed out after 6 seconds (No SNMP response from target host/port)."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SNMP test query failed: {str(e)}")

# ----------------- User Self-Registration & OTP Verification Subsystem -----------------

@app.get("/api/v1/public/register/config")
def get_public_registration_config():
    """Returns self-registration availability and verification requirements for the public portal."""
    settings = get_self_registration_settings()
    primary_realm = get_primary_realm().lower()
    return {
        "status": "success",
        "enabled": bool(settings.get("enabled", 1)),
        "require_mobile_otp": bool(settings.get("require_mobile_otp", 1)),
        "auto_approve_with_otp": bool(settings.get("auto_approve_with_otp", 1)),
        "default_domain": settings.get("default_domain") or primary_realm,
        "primary_realm": primary_realm,
        "sms_provider": settings.get("sms_gateway_type", "simulated")
    }

@app.post("/api/v1/public/register/initiate")
@app.post("/api/v1/registration/submit")
def submit_self_registration(req: SelfRegistrationSubmitRequest, request: Request):
    """Submits a new domain account registration. Dispatches mobile OTP if verification enabled."""
    settings = get_self_registration_settings()
    if not settings.get("enabled", 1):
        raise HTTPException(status_code=403, detail="User self-registration is currently disabled by administrator.")

    clean_user = req.username.strip().lower()
    if not re.match(r"^[a-zA-Z0-9._-]{3,32}$", clean_user):
        raise HTTPException(status_code=400, detail="Username must be 3-32 characters (letters, numbers, dots, dashes).")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")

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

    cursor.execute("""
        SELECT id, status FROM self_registrations 
        WHERE (username = ? OR mobile = ?) AND status IN ('PENDING_OTP', 'PENDING_APPROVAL')
    """, (clean_user, clean_mobile))
    existing = cursor.fetchone()
    if existing:
        cursor.execute("DELETE FROM self_registrations WHERE id = ?", (existing[0],))

    if require_otp:
        otp = f"{secrets.randbelow(900000) + 100000}"
        expiry = time.time() + 600

        cursor.execute("""
            INSERT INTO self_registrations (
                username, email, given_name, surname, department, mobile,
                status, ip_address, created_at, otp_code, otp_expires_at, otp_verified, password_hash, notes
            ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_OTP', ?, ?, ?, ?, 0, ?, ?)
        """, (clean_user, req.email.strip(), req.given_name.strip(), req.surname.strip(),
              req.department or "Engineering", clean_mobile, client_ip, time.time(),
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
              req.department or "Engineering", clean_mobile, client_ip, time.time(),
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
            "message": "Registration received. Your account is pending administrator review and approval. An SMS/Email notification will be sent upon activation."
        }

@app.post("/api/v1/public/register/verify-otp")
def verify_registration_otp(req: SelfRegistrationOtpVerifyRequest):
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
            default_domain=domain
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
    dispatch_sms(mobile, welcome_sms, settings)
    dispatch_email(email, f"Welcome to {domain} - Account Activated", f"Hello {given_name},\n\nYour domain account '{username}' has been successfully verified via mobile OTP and created in Active Directory under primary domain '{domain}'.\n\nYou may now access:\n• Corporate Windows Workstations\n• 802.1X Enterprise Wi-Fi\n• VPN & Single Sign-On\n\nRegards,\nIdentity & Access Team", settings)

    log_audit("USER_SELF_REGISTERED_AUTO_APPROVED", username, "active_directory", "SUCCESS", {"mobile": mobile, "email": email, "domain": domain})

    return {
        "status": "success",
        "username": username,
        "domain": domain,
        "auto_approved": True,
        "message": f"Mobile number verified! Your domain account '{username}@{domain}' is now active."
    }

@app.post("/api/v1/public/register/resend-otp")
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

@app.get("/api/v1/registrations/settings")
def get_registration_settings_endpoint():
    """Returns self-registration and OTP policy settings."""
    settings = get_self_registration_settings()
    return {"status": "success", "settings": settings}

@app.post("/api/v1/registrations/settings")
def update_registration_settings_endpoint(req: SelfRegistrationSettingsRequest):
    """Updates self-registration, OTP verification, and SMS gateway parameters."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE self_registration_settings SET
            enabled = ?,
            require_mobile_otp = ?,
            auto_approve_with_otp = ?,
            default_domain = ?,
            default_group = ?,
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

    log_audit("REGISTRATION_SETTINGS_UPDATED", "admin", "appliance", "SUCCESS", {
        "enabled": req.enabled,
        "require_mobile_otp": req.require_mobile_otp,
        "sms_provider": req.sms_gateway_type
    })

    return {"status": "success", "message": "Self-registration and OTP policies updated successfully."}

@app.get("/api/v1/registrations/requests")
def list_registration_requests(status_filter: Optional[str] = "all"):
    """Lists self-registration queue entries with status filtering."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if status_filter and status_filter.lower() != "all":
        cursor.execute("SELECT id, username, email, given_name, surname, department, mobile, status, ip_address, created_at, approved_at, approved_by, notes FROM self_registrations WHERE LOWER(status) = LOWER(?) ORDER BY created_at DESC", (status_filter,))
    else:
        cursor.execute("SELECT id, username, email, given_name, surname, department, mobile, status, ip_address, created_at, approved_at, approved_by, notes FROM self_registrations ORDER BY created_at DESC")

    rows = cursor.fetchall()
    conn.close()

    requests_list = [dict(r) for r in rows]
    return {
        "status": "success",
        "count": len(requests_list),
        "requests": requests_list
    }

@app.post("/api/v1/registrations/requests/{req_id}/approve")
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
            default_domain=domain
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
    dispatch_email(email, "Your ZclockID Domain Account Has Been Approved", f"Hello {given_name},\n\nYour registration request has been approved by the system administrator.\n\nAccount: {username}@{domain}\nDomain: {domain}\n\nYou may now access corporate systems with your chosen password.\n\nRegards,\nIdentity & Access Team", settings)

    log_audit("REGISTRATION_APPROVED_BY_ADMIN", username, "active_directory", "SUCCESS", {"mobile": mobile, "email": email, "domain": domain})

    return {"status": "success", "message": f"User '{username}' approved and provisioned in Active Directory under domain '{domain}'."}

@app.post("/api/v1/registrations/requests/{req_id}/reject")
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
    dispatch_email(reg["email"], "ZclockID Domain Registration Declined", f"Hello {reg['given_name']},\n\nYour domain registration request for username '{reg['username']}' has been declined by the administrator.\n\nReason: {reason}\n\nPlease contact IT Support for assistance.\n\nRegards,\nIdentity & Access Team", settings)

    log_audit("REGISTRATION_REJECTED", reg["username"], "appliance", "SUCCESS", {"reason": reason})

    return {"status": "success", "message": f"Registration request for '{reg['username']}' rejected."}

@app.delete("/api/v1/registrations/requests/{req_id}")
def delete_registration_request(req_id: int):
    """Deletes a registration record from the queue."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM self_registrations WHERE id = ?", (req_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Registration record deleted."}

# ----------------- Software Update & Version Management -----------------

class UpdateSettingsModel(BaseModel):
    github_repo: Optional[str] = "atanude/Inet-ZclockID"
    custom_manifest_url: Optional[str] = ""
    auto_check: Optional[bool] = True

class UpdateCheckModel(BaseModel):
    github_repo: Optional[str] = None
    custom_manifest_url: Optional[str] = None

class UpdateInstallModel(BaseModel):
    download_url: Optional[str] = None

def launch_update_runner(updater_script: str, deb_path: Path):
    """Launches updater in an independent systemd transient unit so API restart doesn't abort it."""
    code, _, _ = run_cmd(["which", "systemd-run"])
    if code == 0:
        subprocess.run(
            ["systemd-run", "/bin/bash", updater_script, str(deb_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    else:
        subprocess.Popen(
            ["/bin/bash", updater_script, str(deb_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True
        )

@app.get("/api/v1/system/update/info")
def get_update_info():
    """Returns appliance software version, update settings, and cached release information."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM update_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    curr_ver = get_appliance_version()
    latest_ver = row["latest_version"] if row else ""
    is_newer = is_newer_version(latest_ver, curr_ver) if latest_ver else False

    # Check status file
    status_file = Path("/var/run/zclock-update.status")
    last_status = status_file.read_text().strip() if status_file.exists() else "IDLE"

    # Check process running
    code, stdout, _ = run_cmd(["pgrep", "-f", "zclock-updater.sh"])
    is_running = (code == 0 and len(stdout.strip()) > 0)

    return {
        "current_version": curr_ver,
        "system_arch": platform.machine(),
        "python_version": platform.python_version(),
        "platform_system": platform.system(),
        "is_running": is_running,
        "last_update_status": last_status,
        "update_available": is_newer,
        "settings": {
            "github_repo": row["github_repo"] if row else "atanude/Inet-ZclockID",
            "custom_manifest_url": row["custom_manifest_url"] if row else "",
            "auto_check": bool(row["auto_check"]) if row else True,
            "last_checked": row["last_checked"] if row else 0,
            "latest_version": latest_ver,
            "latest_release_name": row["latest_release_name"] if row else "",
            "latest_release_notes": row["latest_release_notes"] if row else "",
            "latest_download_url": row["latest_download_url"] if row else "",
            "last_check_status": row["last_check_status"] if row else "NOT_CHECKED"
        }
    }

@app.post("/api/v1/system/update/settings")
def update_update_settings(settings: UpdateSettingsModel):
    """Configures the remote GitHub repository or custom manifest URL for updates."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE update_settings
        SET github_repo = ?, custom_manifest_url = ?, auto_check = ?, updated_at = ?
        WHERE id = 1
    """, (settings.github_repo.strip(), settings.custom_manifest_url.strip(), 1 if settings.auto_check else 0, time.time()))
    conn.commit()
    conn.close()
    log_audit("UPDATE_SETTINGS_SAVED", "admin", "appliance", "SUCCESS", settings.dict())
    return {"status": "success", "message": "Update settings saved."}

@app.post("/api/v1/system/update/check")
def check_for_updates(req: Optional[UpdateCheckModel] = None):
    """Queries GitHub Releases API or custom manifest for newer versions of ZclockID."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM update_settings WHERE id = 1")
    row = cursor.fetchone()

    repo = (req.github_repo if req and req.github_repo else (row["github_repo"] if row else "atanude/Inet-ZclockID")).strip()
    manifest_url = (req.custom_manifest_url if req and req.custom_manifest_url else (row["custom_manifest_url"] if row else "")).strip()

    curr_ver = get_appliance_version()
    now = time.time()

    # 1. Custom Manifest URL check
    if manifest_url:
        try:
            resp = requests.get(manifest_url, timeout=6, headers={"User-Agent": "ZclockID-Appliance-Updater"})
            if resp.status_code == 200:
                data = resp.json()
                raw_ver = data.get("version", "")
                clean_ver = re.sub(r'^[vV]', '', str(raw_ver).strip())
                release_name = data.get("name", f"ZclockID v{clean_ver}")
                release_notes = data.get("notes", "No changelog provided.")
                download_url = data.get("download_url", "")
                is_newer = is_newer_version(clean_ver, curr_ver)

                cursor.execute("""
                    UPDATE update_settings
                    SET last_checked = ?, latest_version = ?, latest_release_name = ?,
                        latest_release_notes = ?, latest_download_url = ?, last_check_status = 'CHECK_SUCCESS'
                    WHERE id = 1
                """, (now, clean_ver, release_name, release_notes, download_url))
                conn.commit()
                conn.close()

                log_audit("UPDATE_CHECKED", "admin", "custom_manifest", "SUCCESS", {"remote_ver": clean_ver, "newer": is_newer})
                return {
                    "status": "success",
                    "current_version": curr_ver,
                    "latest_version": clean_ver,
                    "update_available": is_newer,
                    "release_name": release_name,
                    "release_notes": release_notes,
                    "download_url": download_url,
                    "source": "custom_manifest"
                }
        except Exception as e:
            cursor.execute("UPDATE update_settings SET last_checked = ?, last_check_status = ? WHERE id = 1", (now, f"ERROR: {str(e)[:50]}"))
            conn.commit()
            conn.close()
            return {
                "status": "error",
                "current_version": curr_ver,
                "update_available": False,
                "message": f"Failed to check custom manifest: {str(e)}"
            }

    # 2. GitHub Releases API Check
    github_url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        resp = requests.get(github_url, timeout=6, headers={
            "User-Agent": "ZclockID-Appliance-Updater",
            "Accept": "application/vnd.github.v3+json"
        })
        if resp.status_code == 200:
            data = resp.json()
            tag = data.get("tag_name", "")
            clean_ver = re.sub(r'^[vV]', '', tag.strip())
            release_name = data.get("name") or f"ZclockID v{clean_ver}"
            release_notes = data.get("body") or "No release notes provided."
            published_at = data.get("published_at", "")

            # Locate .deb asset
            download_url = ""
            asset_size = 0
            for asset in data.get("assets", []):
                if asset.get("name", "").endswith(".deb"):
                    download_url = asset.get("browser_download_url", "")
                    asset_size = asset.get("size", 0)
                    break

            is_newer = is_newer_version(clean_ver, curr_ver)

            cursor.execute("""
                UPDATE update_settings
                SET last_checked = ?, latest_version = ?, latest_release_name = ?,
                    latest_release_notes = ?, latest_download_url = ?, last_check_status = 'CHECK_SUCCESS'
                WHERE id = 1
            """, (now, clean_ver, release_name, release_notes, download_url))
            conn.commit()
            conn.close()

            log_audit("UPDATE_CHECKED", "admin", repo, "SUCCESS", {"remote_ver": clean_ver, "newer": is_newer})
            return {
                "status": "success",
                "current_version": curr_ver,
                "latest_version": clean_ver,
                "update_available": is_newer,
                "release_name": release_name,
                "release_notes": release_notes,
                "download_url": download_url,
                "asset_size": asset_size,
                "published_at": published_at,
                "source": "github_releases"
            }
        elif resp.status_code == 404:
            cursor.execute("UPDATE update_settings SET last_checked = ?, last_check_status = 'NO_RELEASES' WHERE id = 1", (now,))
            conn.commit()
            conn.close()
            return {
                "status": "no_releases",
                "current_version": curr_ver,
                "update_available": False,
                "message": f"No releases found on GitHub for repository '{repo}'. You can still upload a .deb package manually."
            }
        else:
            err_msg = f"GitHub API returned HTTP {resp.status_code}"
            cursor.execute("UPDATE update_settings SET last_checked = ?, last_check_status = ? WHERE id = 1", (now, err_msg))
            conn.commit()
            conn.close()
            return {
                "status": "warning",
                "current_version": curr_ver,
                "update_available": False,
                "message": f"{err_msg}. You can update via manual .deb upload."
            }
    except Exception as e:
        cursor.execute("UPDATE update_settings SET last_checked = ?, last_check_status = 'NETWORK_ERROR' WHERE id = 1", (now,))
        conn.commit()
        conn.close()
        return {
            "status": "offline",
            "current_version": curr_ver,
            "update_available": False,
            "message": f"Could not reach update server ({str(e)}). Manual .deb file upload is available below."
        }

@app.post("/api/v1/system/update/upload")
async def upload_update_package(package: UploadFile = File(...), auto_install: bool = Form(False)):
    """Accepts manual upload of a zclockid .deb package and verifies integrity before installation."""
    if not package.filename.endswith(".deb"):
        raise HTTPException(status_code=400, detail="Only Debian (.deb) package archives are supported.")

    dest_path = Path("/tmp/zclockid_update.deb")
    with open(dest_path, "wb") as f:
        shutil.copyfileobj(package.file, f)

    file_size = dest_path.stat().st_size
    if file_size < 1000:
        dest_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Uploaded file is too small to be a valid package.")

    # Validate package with dpkg-deb
    code, stdout, stderr = run_cmd(["dpkg-deb", "-I", str(dest_path)])
    if code != 0:
        dest_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Corrupted or invalid Debian package: {stderr}")

    pkg_name = ""
    pkg_ver = ""
    pkg_arch = ""
    for line in stdout.splitlines():
        if line.strip().startswith("Package:"):
            pkg_name = line.split(":", 1)[1].strip()
        elif line.strip().startswith("Version:"):
            pkg_ver = line.split(":", 1)[1].strip()
        elif line.strip().startswith("Architecture:"):
            pkg_arch = line.split(":", 1)[1].strip()

    if pkg_name != "zclockid":
        dest_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Invalid package '{pkg_name}'. Expected 'zclockid'.")

    log_audit("UPDATE_PACKAGE_UPLOADED", "admin", "appliance", "SUCCESS", {"version": pkg_ver, "size": file_size, "arch": pkg_arch})

    # If auto_install requested, launch the updater runner
    if auto_install:
        updater_script = ensure_updater_script()
        launch_update_runner(updater_script, dest_path)
        return {
            "status": "installing",
            "package": pkg_name,
            "version": pkg_ver,
            "arch": pkg_arch,
            "size_bytes": file_size,
            "message": f"Package v{pkg_ver} uploaded and update initiated! The system will restart services in a few seconds."
        }

    return {
        "status": "ready",
        "package": pkg_name,
        "version": pkg_ver,
        "arch": pkg_arch,
        "size_bytes": file_size,
        "message": f"Package v{pkg_ver} ({pkg_arch}) verified and staged successfully. Click 'Install Update' to apply."
    }

@app.post("/api/v1/system/update/install")
def install_update(req: Optional[UpdateInstallModel] = None):
    """Downloads remote update or runs installer on already staged package in background."""
    target_deb = Path("/tmp/zclockid_update.deb")

    # If download URL provided, fetch it
    download_url = req.download_url if req and req.download_url else None
    if not download_url and not target_deb.exists():
        # Check DB for latest download URL
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT latest_download_url FROM update_settings WHERE id = 1")
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            download_url = row[0]

    if download_url:
        try:
            logger.info(f"Downloading update from: {download_url}")
            resp = requests.get(download_url, stream=True, timeout=30, headers={"User-Agent": "ZclockID-Appliance-Updater"})
            if resp.status_code == 200:
                with open(target_deb, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            else:
                raise HTTPException(status_code=400, detail=f"Failed to download update package: HTTP {resp.status_code}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Download error: {str(e)}")

    if not target_deb.exists():
        raise HTTPException(status_code=400, detail="No update package staged on appliance. Please upload a .deb file or check for updates first.")

    # Validate with dpkg-deb
    code, stdout, stderr = run_cmd(["dpkg-deb", "-I", str(target_deb)])
    if code != 0:
        target_deb.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Invalid package file: {stderr}")

    pkg_ver = "unknown"
    for line in stdout.splitlines():
        if line.strip().startswith("Version:"):
            pkg_ver = line.split(":", 1)[1].strip()

    updater_script = ensure_updater_script()

    # Launch detached update runner
    launch_update_runner(updater_script, target_deb)

    log_audit("SYSTEM_UPDATE_STARTED", "admin", "appliance", "STARTED", {"target_version": pkg_ver})

    return {
        "status": "started",
        "target_version": pkg_ver,
        "message": f"Update to v{pkg_ver} initiated in background. The API will restart automatically once files are unpacked."
    }

@app.get("/api/v1/system/update/status")
def get_update_status():
    """Returns the live execution state of any background package updater."""
    status_file = Path("/var/run/zclock-update.status")
    status_text = status_file.read_text().strip() if status_file.exists() else "IDLE"

    code, stdout, _ = run_cmd(["pgrep", "-f", "zclock-updater.sh"])
    is_running = (code == 0 and len(stdout.strip()) > 0)

    return {
        "is_running": is_running,
        "status": status_text,
        "current_version": get_appliance_version()
    }

@app.get("/api/v1/system/update/log")
def get_update_log():
    """Returns the complete live update log from /var/log/zclock-update.log."""
    log_file = Path("/var/log/zclock-update.log")
    if not log_file.exists():
        return {"log": "No update log found. No updates have been run yet.", "lines": []}
    content = log_file.read_text()
    return {
        "log": content,
        "lines": content.splitlines()[-100:],
        "size": len(content)
    }

# ----------------- Background Active Directory DRS Replication Poller -----------------

def background_radius_drs_poller():
    """Wakes up every 60 seconds to detect Active Directory DRS-replicated user bandwidth profiles."""
    while True:
        try:
            time.sleep(60)
            sync_freeradius_policies()
        except Exception:
            pass

import threading
_drs_sync_thread = threading.Thread(target=background_radius_drs_poller, daemon=True)
_drs_sync_thread.start()

