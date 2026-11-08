"""
ZclockID Enterprise Management Appliance - Core Configuration & Paths
Implements unified root (/zclockid) with graceful fallback for live migration.
"""

import os
from pathlib import Path

# Base Appliance Root Directory
ZCLOCKID_ROOT = Path(os.environ.get("ZCLOCKID_ROOT", "/zclockid"))

# Primary Directories
CONFIG_DIR = Path(os.environ.get("ZCLOCKID_CONFIG_DIR", ZCLOCKID_ROOT / "config" if ZCLOCKID_ROOT.exists() else "/etc/zclockid"))
DATA_DIR = Path(os.environ.get("ZCLOCKID_DATA_DIR", ZCLOCKID_ROOT / "data" if ZCLOCKID_ROOT.exists() else "/var/lib/zclockid"))
LOG_DIR = Path(os.environ.get("ZCLOCKID_LOG_DIR", ZCLOCKID_ROOT / "logs" if ZCLOCKID_ROOT.exists() else "/var/log/zclockid"))
WEB_DIR = Path(os.environ.get("ZCLOCKID_WEB_DIR", ZCLOCKID_ROOT / "web" if ZCLOCKID_ROOT.exists() else "/opt/zclockid/web"))
TEMPLATES_DIR = Path(os.environ.get("ZCLOCKID_TEMPLATES_DIR", ZCLOCKID_ROOT / "templates" if ZCLOCKID_ROOT.exists() else "/opt/zclockid/templates"))
BACKUP_DIR = Path(os.environ.get("ZCLOCKID_BACKUP_DIR", DATA_DIR / "backups"))

# Ensure base directories exist
for d in [DATA_DIR, LOG_DIR, BACKUP_DIR]:
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

# Database & Key State Files
DB_PATH = DATA_DIR / "zclockid.db"
SETUP_LOCK_FILE = CONFIG_DIR / "setup.lock"
AD_CREDS_FILE = CONFIG_DIR / "ad_creds"
AZURE_CONFIG_FILE = CONFIG_DIR / "azure-sync.json"
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

# Product Metadata
APP_NAME = "ZclockID Enterprise Management Appliance"
APP_VERSION = "1.2.2"
APP_REPO = "atanumaj/zclockid"
OFFICIAL_MANIFEST_URL = "https://raw.githubusercontent.com/atanumaj/zclockid/master/version-manifest.json"
OFFICIAL_CHANNEL = "stable"
DEFAULT_REALM = ""
