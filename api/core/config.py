"""
ZclockID Enterprise Management Appliance - Core Configuration & Paths
Implements unified root (/zclockid) with graceful fallback for live migration.
"""

import os
import tempfile
from pathlib import Path

# Base Appliance Root Directory
ZCLOCKID_ROOT = Path(os.environ.get("ZCLOCKID_ROOT", "/zclockid"))

# Primary Directories Resolution
def _resolve_data_dir() -> Path:
    custom = os.environ.get("ZCLOCKID_DATA_DIR")
    if custom:
        return Path(custom)
    z_db = Path("/zclockid/data/zclockid.db")
    std_db = Path("/var/lib/zclockid/zclockid.db")
    if z_db.exists() and (z_db.stat().st_size > 0 or not std_db.exists()):
        return Path("/zclockid/data")
    if std_db.exists():
        return Path("/var/lib/zclockid")
    if Path("/zclockid/data").exists():
        return Path("/zclockid/data")
    return Path("/var/lib/zclockid")

def _resolve_config_dir() -> Path:
    custom = os.environ.get("ZCLOCKID_CONFIG_DIR")
    if custom:
        return Path(custom)
    if (Path("/zclockid/config/setup.lock")).exists() or (Path("/zclockid/config/ad_creds")).exists():
        return Path("/zclockid/config")
    if Path("/etc/zclockid").exists():
        return Path("/etc/zclockid")
    if Path("/zclockid/config").exists():
        return Path("/zclockid/config")
    return Path("/etc/zclockid")

def _resolve_web_dir() -> Path:
    custom = os.environ.get("ZCLOCKID_WEB_DIR")
    if custom:
        return Path(custom)
    if Path("/opt/zclockid/web").exists():
        return Path("/opt/zclockid/web")
    if Path("/zclockid/web").exists():
        return Path("/zclockid/web")
    return Path("/opt/zclockid/web")

def _resolve_templates_dir() -> Path:
    custom = os.environ.get("ZCLOCKID_TEMPLATES_DIR")
    if custom:
        return Path(custom)
    if Path("/etc/zclockid/templates").exists():
        return Path("/etc/zclockid/templates")
    if Path("/opt/zclockid/templates").exists():
        return Path("/opt/zclockid/templates")
    if Path("/zclockid/templates").exists():
        return Path("/zclockid/templates")
    return Path("/etc/zclockid/templates")

CONFIG_DIR = _resolve_config_dir()
DATA_DIR = _resolve_data_dir()
LOG_DIR = Path(os.environ.get("ZCLOCKID_LOG_DIR", "/var/log/zclockid" if Path("/var/log/zclockid").exists() else (ZCLOCKID_ROOT / "logs" if (ZCLOCKID_ROOT / "logs").exists() else "/var/log/zclockid")))
WEB_DIR = _resolve_web_dir()
TEMPLATES_DIR = _resolve_templates_dir()
BACKUP_DIR = Path(os.environ.get("ZCLOCKID_BACKUP_DIR", DATA_DIR / "backups"))

def _resolve_updates_dir() -> Path:
    custom = os.environ.get("ZCLOCKID_UPDATES_DIR")
    if custom:
        p = Path(custom)
        try:
            p.mkdir(parents=True, exist_ok=True)
            os.chmod(p, 0o700)
        except Exception:
            pass
        return p
    default_p = Path("/var/lib/zclockid/updates")
    try:
        default_p.mkdir(parents=True, exist_ok=True)
        os.chmod(default_p, 0o700)
        return default_p
    except (PermissionError, OSError):
        fb = Path(tempfile.gettempdir()) / "zclockid_updates"
        try:
            fb.mkdir(parents=True, exist_ok=True)
            os.chmod(fb, 0o700)
        except Exception:
            pass
        return fb

UPDATES_DIR = _resolve_updates_dir()

# Ensure base directories exist
for d in [DATA_DIR, LOG_DIR, BACKUP_DIR, UPDATES_DIR]:
    try:
        d.mkdir(parents=True, exist_ok=True)
        if d == UPDATES_DIR:
            os.chmod(d, 0o700)
    except Exception:
        pass

# Database & Key State Files
def _resolve_db_path() -> Path:
    v_db = Path("/var/lib/zclockid/zclockid.db")
    z_db = Path("/zclockid/data/zclockid.db")
    if v_db.exists() and v_db.stat().st_size > 0:
        return v_db
    if z_db.exists() and z_db.stat().st_size > 0:
        return z_db
    return DATA_DIR / "zclockid.db"

def _resolve_setup_lock_file() -> Path:
    for candidate in [
        CONFIG_DIR / "setup.lock",
        Path("/etc/zclockid/setup.lock"),
        Path("/zclockid/config/setup.lock"),
        Path("/var/lib/zclockid/.setup_locked"),
        Path("/etc/zclockid/.setup_locked"),
    ]:
        if candidate.exists():
            return candidate
    return CONFIG_DIR / "setup.lock"

DB_PATH = _resolve_db_path()
SETUP_LOCK_FILE = _resolve_setup_lock_file()
AD_CREDS_FILE = Path("/zclockid/config/ad_creds") if Path("/zclockid/config/ad_creds").exists() else (Path("/etc/zclockid/ad_creds") if Path("/etc/zclockid/ad_creds").exists() else CONFIG_DIR / "ad_creds")
AZURE_CONFIG_FILE = Path("/etc/zclockid/azure-sync.json") if Path("/etc/zclockid/azure-sync.json").exists() else (Path("/zclockid/config/azure-sync.json") if Path("/zclockid/config/azure-sync.json").exists() else CONFIG_DIR / "azure-sync.json")
AZURE_STATUS_FILE = Path("/var/run/zclock-azuresync.status")
SYSVOL_HEALTH_FILE = Path("/var/run/zclock-sysvol.health")

# Active Directory & Sysvol Storage
SAMBA_LDB_PATH = Path("/var/lib/samba/private/sam.ldb")
PHYSICAL_SYSVOL_DIR = Path("/var/lib/samba/sysvol")
APPLIANCE_SYSVOL_SYMLINK = DATA_DIR / "sysvol"

# Native Subsystem Engine Configurations
SMB_CONF_FILE = Path("/etc/samba/smb.conf")
BIND_OPTIONS_FILE = Path("/etc/bind/named.conf.options")
RADIUS_CLIENTS_FILE = Path("/etc/freeradius/3.0/clients.conf")
RADIUS_AUTHORIZE_FILE = Path("/etc/freeradius/3.0/mods-config/files/authorize")
RADIUS_USERS_FILE = Path("/etc/freeradius/3.0/users")
RADIUS_MSCHAP_FILE = Path("/etc/freeradius/3.0/mods-available/mschap")
RADIUS_EAP_FILE = Path("/etc/freeradius/3.0/mods-available/eap")
RADIUS_SERVER_CERT = Path("/etc/freeradius/3.0/certs/server.pem")
RADIUS_CA_CERT = Path("/etc/freeradius/3.0/certs/ca.pem")

# Time Synchronization (Chrony)
CHRONY_CONF_DIR = Path("/etc/chrony/conf.d")
CHRONY_SOURCES_DIR = Path("/etc/chrony/sources.d")
ZCLOCK_NTP_CONF = CHRONY_CONF_DIR / "zclockid-ntp-server.conf"
ZCLOCK_NTP_SOURCES = CHRONY_SOURCES_DIR / "zclockid-upstream.sources"

# SNMP Agent Configuration
SNMPD_CONF_FILE = Path("/etc/snmp/snmpd.conf")

# Sysadmin Overrides Directory
OVERRIDES_DIR = CONFIG_DIR / "overrides.d"
try:
    OVERRIDES_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

# Product Metadata & Author Fingerprint
APP_NAME = "ZclockID Enterprise Management Appliance"
APP_VERSION = "1.5.9"
APP_AUTHOR = "Atanu Majumdar (@atanumaj)"
APP_COPYRIGHT = "Copyright (c) 2026 Atanu Majumdar. All Rights Reserved."
APP_REPO = "atanumaj/zclockid"
OFFICIAL_MANIFEST_URL = "https://raw.githubusercontent.com/atanumaj/zclockid/gh-pages/version-manifest.json"
OFFICIAL_CHANNEL = "stable"
DEFAULT_REALM = ""
APPLIANCE_FINGERPRINT = "ZCLOCKID-ATANUMAJ-2026-ED25519"
