"""
ZclockID Appliance System, Services, Telemetry, Backups, and Lifecycle Router
"""

import os
import re
import io
import time
import json
import shutil
import tarfile
import zipfile
import platform
import datetime
import sqlite3
import subprocess
import requests
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, status
from fastapi.responses import FileResponse, PlainTextResponse

from api.core.config import (
    DB_PATH,
    BACKUP_DIR,
    APP_VERSION,
    APP_REPO,
    OFFICIAL_MANIFEST_URL,
    OFFICIAL_CHANNEL,
    PHYSICAL_SYSVOL_DIR,
    ZCLOCKID_ROOT,
    SNMPD_CONF_FILE
)
from api.services.system_service import (
    run_cmd,
    check_systemd_service,
    log_audit,
    get_appliance_version
)
from api.services.samba_service import get_ad_creds
from api.schemas.system_schema import (
    ServiceActionRequest,
    SystemIdentityUpdateRequest,
    BackupCreateRequest,
    BackupRestoreRequest,
    BackupInspectRequest,
    SnmpConfigRequest,
    SnmpTestQueryRequest,
    UpdateSettingsModel,
    UpdateCheckModel,
    UpdateInstallModel
)

router = APIRouter(tags=["System Administration & Maintenance"])

ALL_MANAGED_SERVICES = [
    "samba-ad-dc",
    "bind9",
    "freeradius",
    "chrony",
    "zclock-sysvold",
    "zclock-azuresync",
    "zclock-exporter",
    "zclock-api",
    "nginx",
    "snmpd"
]

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
    standard_paths = [
        str(ZCLOCKID_ROOT / "daemons" / "zclock-updater"),
        str(ZCLOCKID_ROOT / "daemons" / "zclock-updater.sh"),
        "/opt/zclockid/scripts/zclock-updater.sh"
    ]
    for sp in standard_paths:
        if os.path.exists(sp) and os.access(sp, os.X_OK):
            return sp

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
echo "${PKG_VER}" > /zclockid/VERSION 2>/dev/null || true
systemctl daemon-reload >> "${LOG_FILE}" 2>&1 || true
systemctl restart zclock-api.service >> "${LOG_FILE}" 2>&1 || true
echo "SUCCESS" > "${STATUS_FILE}"
echo "=== Update Completed Successfully at $(date) ===" >> "${LOG_FILE}"
"""
    with open(fallback_path, "w") as f:
        f.write(updater_script_content)
    os.chmod(fallback_path, 0o755)
    return fallback_path

def launch_update_runner(updater_script: str, deb_path: Path):
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
            start_new_session=True
        )

def ensure_os_updater_script():
    installed_path = "/opt/zclockid/scripts/zclock-os-updater.sh"
    if os.path.exists(installed_path):
        return installed_path
    repo_path = "/Users/atanu/Documents/GitHub/ZclockID/scripts/zclock-os-updater.sh"
    if os.path.exists(repo_path):
        return repo_path
    fallback_path = "/tmp/zclock-os-updater.sh"
    updater_script_content = """#!/usr/bin/env bash
set -o pipefail
LOG_FILE="/var/log/zclock-os-update.log"
STATUS_FILE="/var/run/zclock-os-update.status"
echo "UPGRADING" > "${STATUS_FILE}"
echo "=== ZclockID Debian/Ubuntu OS Package Upgrade Initiated at $(date) ===" > "${LOG_FILE}"
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
apt-get update >> "${LOG_FILE}" 2>&1
if apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade >> "${LOG_FILE}" 2>&1; then
    if [ -f "/var/run/reboot-required" ]; then
        echo "COMPLETED_REBOOT_REQUIRED" > "${STATUS_FILE}"
    else
        echo "COMPLETED" > "${STATUS_FILE}"
    fi
else
    apt-get install -f -y >> "${LOG_FILE}" 2>&1 || true
    echo "FAILED" > "${STATUS_FILE}"
fi
"""
    with open(fallback_path, "w") as f:
        f.write(updater_script_content)
    os.chmod(fallback_path, 0o755)
    return fallback_path

def launch_os_update_runner(updater_script: str, mode: str = "all"):
    code, _, _ = run_cmd(["which", "systemd-run"])
    if code == 0:
        subprocess.run(
            ["systemd-run", "/bin/bash", updater_script, mode],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    else:
        subprocess.Popen(
            ["/bin/bash", updater_script, mode],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )

def read_manifest_from_tar(tar_path: Path) -> Optional[dict]:
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


# ----------------- Dashboard & System Status -----------------

@router.get("/api/v1/system/status")
def get_system_status():
    """Returns comprehensive appliance health, engine statuses, PIDs, memory, and ports."""
    services = {
        "samba_ad_dc": check_systemd_service("samba-ad-dc"),
        "bind9": check_systemd_service("bind9"),
        "freeradius": check_systemd_service("freeradius"),
        "chrony": check_systemd_service("chrony"),
        "zclock_sysvold": check_systemd_service("zclock-sysvold"),
        "zclock_azuresync": check_systemd_service("zclock-azuresync"),
        "zclock_exporter": check_systemd_service("zclock-exporter"),
        "zclock_api": check_systemd_service("zclock-api"),
        "nginx": check_systemd_service("nginx"),
        "snmpd": check_systemd_service("snmpd")
    }

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
        "DoH Internal HTTP": 8053,
        "Prometheus Exporter": 9101
    }

    import psutil
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    active_count = sum(1 for s in services.values() if s.get("status") == "active")
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


# ----------------- Module Logs & Live Controls -----------------

@router.get("/api/v1/services")
def list_managed_services():
    """Lists all 9 managed system services with metadata, role category, ports, runtime state, and boot status."""
    catalog = [
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
            "role": "Bi-directional Sysvol Replication & Windows NTACL Self-Healing (Go Native)",
            "ports": [],
            "unit": "zclock-sysvold.service"
        },
        {
            "id": "zclock-exporter",
            "name": "Telemetry & Prometheus Exporter",
            "category": "custom_built",
            "category_label": "PROMETHEUS ENGINE",
            "role": "High-Frequency System & Daemon Telemetry Exporter (Go Native)",
            "ports": [9101],
            "unit": "zclock-exporter.service"
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
            "name": "SNMP Telemetry",
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

@router.get("/api/v1/services/{service_name}/logs")
def get_service_logs(service_name: str, lines: int = 50):
    """Retrieves live journalctl log lines for any engine service."""
    if service_name not in ALL_MANAGED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not allowed.")
    code, stdout, stderr = run_cmd(["journalctl", "-u", service_name, "-n", str(min(lines, 200)), "--no-pager"], timeout=10)
    return {"service": service_name, "logs": stdout or stderr or "No logs recorded yet."}

@router.post("/api/v1/services/{service_name}/control")
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

@router.post("/api/v1/services/{service_name}/restart")
def restart_subsystem_service(service_name: str):
    if service_name not in ALL_MANAGED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not managed by ZclockID.")
    code, stdout, stderr = run_cmd(["systemctl", "restart", service_name], timeout=15)
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to restart {service_name}: {stderr or stdout}")
    log_audit("SERVICE_RESTART", "admin", service_name, "SUCCESS", {})
    return {"status": "success", "message": f"Service '{service_name}' restarted successfully."}


# ----------------- System Identity & Host Management -----------------

@router.post("/api/v1/system/identity")
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
                realm = ""
                if os.path.exists("/etc/samba/smb.conf"):
                    with open("/etc/samba/smb.conf") as f:
                        for l in f:
                            if "realm =" in l:
                                realm = l.split("=")[1].strip().lower()
                fqdn_str = f"{new_hn}.{realm}\t{new_hn}" if realm else new_hn
                hosts_content = re.sub(r'127\.0\.1\.1\s+.*', f'127.0.1.1\t{fqdn_str}', hosts_content)
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
    return {"status": "success", "actions": actions_taken}

@router.post("/api/v1/system/reboot")
def reboot_appliance():
    log_audit("SYSTEM_REBOOT", "admin", "appliance", "SUCCESS", {})
    run_cmd(["systemctl", "reboot"])
    return {"status": "success", "message": "Appliance reboot signal sent. Restarting in 5 seconds."}


# ----------------- Audit Reports -----------------

@router.get("/api/v1/reports/summary")
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

@router.get("/api/v1/reports/audit-events")
def get_audit_events_report(limit: int = 50, offset: int = 0):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"count": len(rows), "events": rows}

@router.get("/api/v1/reports/export/csv")
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


# ----------------- Backup & Disaster Recovery -----------------

@router.get("/api/v1/backups")
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
            "hostname": manifest.get("hostname", os.uname().nodename) if manifest else "unknown",
            "realm": manifest.get("realm", "UNKNOWN") if manifest else "unknown",
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

@router.post("/api/v1/backups/create")
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
        from api.routers.domain import get_domain_info
        domain_info = get_domain_info()
        realm = domain_info.get("realm", "UNKNOWN")
        hostname = domain_info.get("hostname", os.uname().nodename)
        domain_sid = domain_info.get("domain_sid", "Unknown")

        manifest = {
            "backup_id": ts,
            "filename": archive_name,
            "backup_type": b_type,
            "description": req.description or "ZclockID backup",
            "created_at": datetime.datetime.now().isoformat(),
            "hostname": hostname,
            "realm": realm,
            "netbios_name": domain_info.get("netbios_name", "UNKNOWN"),
            "domain_sid": domain_sid,
            "functional_levels": {
                "domain_level": domain_info.get("domain_functional_level", "Windows Server 2016"),
                "forest_level": domain_info.get("forest_functional_level", "Windows Server 2016")
            },
            "appliance_version": APP_VERSION,
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

        # Stage /zclockid/config directory
        cfg_backup_dir = appliance_dir / "config"
        cfg_backup_dir.mkdir(parents=True, exist_ok=True)
        from api.core.config import CONFIG_DIR
        if CONFIG_DIR.exists():
            for item in CONFIG_DIR.iterdir():
                if item.is_file():
                    shutil.copy2(item, cfg_backup_dir / item.name)

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

            if PHYSICAL_SYSVOL_DIR.exists():
                shutil.copytree(PHYSICAL_SYSVOL_DIR, staging_dir / "sysvol", dirs_exist_ok=True)

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

@router.get("/api/v1/backups/download/{filename}")
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

@router.post("/api/v1/backups/upload")
async def upload_backup(file: UploadFile = File(...)):
    """Uploads an external backup archive (.tar.gz, .tgz, .zip, .tar) into the appliance backup repository."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(file.filename).name
    lower_name = safe_name.lower()

    if not (lower_name.endswith(".tar.gz") or lower_name.endswith(".tgz") or lower_name.endswith(".zip") or lower_name.endswith(".tar") or lower_name.endswith(".gz")):
        raise HTTPException(status_code=400, detail="Invalid file format. Must be a .tar.gz, .tgz, .zip, .tar, or .gz backup archive.")

    try:
        if lower_name.endswith(".zip"):
            temp_zip = Path("/tmp") / f"upload_{int(time.time())}_{safe_name}"
            with open(temp_zip, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            with zipfile.ZipFile(temp_zip, "r") as zf:
                zip_members = zf.namelist()
                tar_inside = [m for m in zip_members if m.endswith(".tar.gz") or m.endswith(".tgz")]
                if tar_inside:
                    inner_name = Path(tar_inside[0]).name
                    final_name = inner_name if not (BACKUP_DIR / inner_name).exists() else f"uploaded_{inner_name}"
                    target_path = BACKUP_DIR / final_name
                    with zf.open(tar_inside[0]) as src, open(target_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                else:
                    extract_staging = Path("/tmp") / f"zip_stage_{int(time.time())}"
                    zf.extractall(extract_staging)

                    extract_root = extract_staging
                    entries = [e for e in extract_staging.iterdir() if not e.name.startswith("__MACOSX") and not e.name.startswith(".")]
                    if len(entries) == 1 and entries[0].is_dir():
                        extract_root = entries[0]

                    base_stem = safe_name[:-4]
                    if not base_stem.startswith("zclockid-"):
                        base_stem = f"zclockid-{base_stem}"
                    final_name = f"{base_stem}.tar.gz"
                    target_path = BACKUP_DIR / final_name

                    with tarfile.open(target_path, "w:gz") as tar:
                        for item in extract_root.iterdir():
                            if not item.name.startswith("__MACOSX") and not item.name.startswith("."):
                                tar.add(item, arcname=item.name)

                    shutil.rmtree(extract_staging, ignore_errors=True)

            temp_zip.unlink(missing_ok=True)
            safe_name = target_path.name

        elif lower_name.endswith(".tar"):
            temp_tar = Path("/tmp") / f"upload_{int(time.time())}_{safe_name}"
            with open(temp_tar, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            final_name = f"{safe_name[:-4]}.tar.gz"
            target_path = BACKUP_DIR / final_name
            with tarfile.open(temp_tar, "r:") as src_tar, tarfile.open(target_path, "w:gz") as dst_tar:
                for member in src_tar.getmembers():
                    f = src_tar.extractfile(member) if member.isreg() else None
                    dst_tar.addfile(member, f)

            temp_tar.unlink(missing_ok=True)
            safe_name = target_path.name

        else: # .tar.gz or .tgz
            target_path = BACKUP_DIR / safe_name
            with open(target_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

        manifest = read_manifest_from_tar(target_path)
        if not manifest and not tarfile.is_tarfile(target_path):
            target_path.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZclockID backup archive.")

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
        if 'target_path' in locals() and target_path.exists():
            target_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Failed to process uploaded backup: {str(e)}")

@router.post("/api/v1/backups/inspect")
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

@router.post("/api/v1/backups/restore")
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

        # 2. Restore Appliance config files
        zclock_backup_dir = restore_staging / "appliance" / "config"
        if not zclock_backup_dir.exists():
            zclock_backup_dir = restore_staging / "appliance" / "etc_zclockid"
        if zclock_backup_dir.exists():
            from api.core.config import CONFIG_DIR
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            for item in zclock_backup_dir.iterdir():
                if item.is_file():
                    shutil.copy2(item, CONFIG_DIR / item.name)
            restored_components.append(f"Appliance credentials and state ({CONFIG_DIR})")

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
            shutil.copytree(restore_staging / "sysvol", PHYSICAL_SYSVOL_DIR, dirs_exist_ok=True)
            restored_components.append(f"Active Directory Sysvol policies ({PHYSICAL_SYSVOL_DIR})")

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

@router.delete("/api/v1/backups/{filename}")
def delete_backup(filename: str):
    """Deletes a backup archive from the appliance repository."""
    safe_name = Path(filename).name
    target_path = BACKUP_DIR / safe_name
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Backup file not found.")

    target_path.unlink()
    log_audit("BACKUP_DELETED", "admin", "appliance", "SUCCESS", {"filename": safe_name})
    return {"status": "success", "message": f"Backup archive '{safe_name}' deleted successfully."}


# ----------------- SNMP Service Management & Telemetry -----------------

@router.get("/api/v1/snmp/status")
def get_snmp_status():
    """Returns SNMP daemon operational state, listening ports, and real-time enterprise telemetry OID values."""
    is_active = subprocess.run(["systemctl", "is-active", "--quiet", "snmpd"]).returncode == 0
    is_enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "snmpd"]).returncode == 0

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

@router.get("/api/v1/snmp/config")
def get_snmp_config():
    """Parses SNMP configuration and returns active SNMP settings."""
    conf_path = SNMPD_CONF_FILE
    is_active = subprocess.run(["systemctl", "is-active", "--quiet", "snmpd"]).returncode == 0

    config = {
        "enabled": is_active,
        "agent_address": "udp:161,udp6:[::1]:161",
        "sys_location": "Primary Datacenter",
        "sys_contact": "admin@example.com",
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
        except Exception:
            pass

    return {"status": "success", "config": config}

@router.post("/api/v1/snmp/config")
def update_snmp_config(req: SnmpConfigRequest):
    """Updates /etc/snmp/snmpd.conf, manages snmpd service state, and writes audit log."""
    conf_path = SNMPD_CONF_FILE
    conf_dir = conf_path.parent
    conf_dir.mkdir(parents=True, exist_ok=True)

    telemetry_dest = Path("/usr/local/bin/zclock-telemetry.sh")
    repo_telemetry = ZCLOCKID_ROOT / "scripts" / "zclock-telemetry.sh"
    if repo_telemetry.exists() and not telemetry_dest.exists():
        try:
            shutil.copy2(repo_telemetry, telemetry_dest)
            telemetry_dest.chmod(0o755)
        except Exception:
            pass

    subnets = [s.strip() for s in req.allowed_subnets.split(",") if s.strip()]
    if not subnets:
        subnets = ["127.0.0.1"]

    lines = [
        "# /etc/snmp/snmpd.conf",
        "# ZclockID Appliance SNMP Telemetry Configuration",
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
        raise HTTPException(status_code=500, detail=f"Failed to write snmpd.conf: {str(e)}")

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

@router.post("/api/v1/snmp/test-query")
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


# ----------------- System Updates & Hotfix Manager -----------------

@router.get("/api/v1/system/update/info")
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

    status_file = Path("/var/run/zclock-update.status")
    last_status = status_file.read_text().strip() if status_file.exists() else "IDLE"

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
        "is_channel_locked": True,
        "official_channel": OFFICIAL_CHANNEL,
        "official_repo": APP_REPO,
        "official_manifest_url": OFFICIAL_MANIFEST_URL,
        "settings": {
            "github_repo": APP_REPO,
            "channel": OFFICIAL_CHANNEL,
            "manifest_url": OFFICIAL_MANIFEST_URL,
            "is_locked": True,
            "custom_manifest_url": "",
            "auto_check": bool(row["auto_check"]) if row else True,
            "last_checked": row["last_checked"] if row else 0,
            "latest_version": latest_ver,
            "latest_release_name": row["latest_release_name"] if row else "",
            "latest_release_notes": row["latest_release_notes"] if row else "",
            "latest_download_url": row["latest_download_url"] if row else "",
            "last_check_status": row["last_check_status"] if row else "NOT_CHECKED"
        }
    }

@router.post("/api/v1/system/update/settings")
def update_update_settings(settings: UpdateSettingsModel):
    """Saves update preferences. Upstream channel is locked to official repository."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE update_settings
        SET github_repo = ?, auto_check = ?, updated_at = ?
        WHERE id = 1
    """, (APP_REPO, 1 if settings.auto_check else 0, time.time()))
    conn.commit()
    conn.close()
    log_audit("UPDATE_SETTINGS_SAVED", "admin", "appliance", "SUCCESS", {"auto_check": settings.auto_check})
    return {"status": "success", "message": "Update preferences saved. Channel is permanently locked to official upstream."}

@router.post("/api/v1/system/update/check")
def check_for_updates(req: Optional[UpdateCheckModel] = None):
    """Queries official upstream manifest or GitHub for newer versions of ZclockID."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM update_settings WHERE id = 1")
    row = cursor.fetchone()

    curr_ver = get_appliance_version()
    now = time.time()

    # 1. Official GitHub Raw Manifest (Primary: Fast, Continuous Delivery, Zero Rate-Limits)
    manifest_urls = [
        f"{OFFICIAL_MANIFEST_URL}?t={int(now)}"
    ]
    if row and row["custom_manifest_url"] and row["custom_manifest_url"].strip():
        manifest_urls.insert(0, f"{row['custom_manifest_url'].strip()}?t={int(now)}")

    for m_url in manifest_urls:
        try:
            resp = requests.get(m_url, timeout=8, headers={"User-Agent": "ZclockID-Appliance-Updater"})
            if resp.status_code == 200:
                data = resp.json()
                raw_ver = data.get("version", "")
                clean_ver = re.sub(r'^[vV]', '', str(raw_ver).strip())
                release_name = data.get("name", f"ZclockID v{clean_ver}")
                release_notes = data.get("notes", data.get("summary", "No changelog provided."))
                release_type = data.get("release_type", "patch")
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

                log_audit("UPDATE_CHECKED", "admin", "official_manifest", "SUCCESS", {"remote_ver": clean_ver, "newer": is_newer, "type": release_type})
                return {
                    "status": "success",
                    "current_version": curr_ver,
                    "latest_version": clean_ver,
                    "update_available": is_newer,
                    "release_type": release_type,
                    "release_name": release_name,
                    "release_notes": release_notes,
                    "download_url": download_url,
                    "source": "official_manifest"
                }
        except Exception as e:
            logging.getLogger("uvicorn.error").warning(f"Manifest check error for {m_url}: {e}")

    # 2. Secondary Fallback: GitHub Releases API
    repo = APP_REPO
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
                "release_type": "standard",
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
                "message": f"Appliance is running current version v{curr_ver}. Upstream repository is up to date."
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

@router.post("/api/v1/system/update/upload")
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

@router.post("/api/v1/system/update/install")
def install_update(req: Optional[UpdateInstallModel] = None):
    """Downloads remote update or runs installer on already staged package in background."""
    target_deb = Path("/tmp/zclockid_update.deb")

    download_url = req.download_url if req and req.download_url else None
    if not download_url and not target_deb.exists():
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT latest_download_url FROM update_settings WHERE id = 1")
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            download_url = row[0]

    if download_url:
        try:
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

    code, stdout, stderr = run_cmd(["dpkg-deb", "-I", str(target_deb)])
    if code != 0:
        target_deb.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Invalid package file: {stderr}")

    pkg_ver = "unknown"
    for line in stdout.splitlines():
        if line.strip().startswith("Version:"):
            pkg_ver = line.split(":", 1)[1].strip()

    updater_script = ensure_updater_script()
    launch_update_runner(updater_script, target_deb)
    log_audit("SYSTEM_UPDATE_STARTED", "admin", "appliance", "STARTED", {"target_version": pkg_ver})

    return {
        "status": "started",
        "target_version": pkg_ver,
        "message": f"Update to v{pkg_ver} initiated in background. The API will restart automatically once files are unpacked."
    }

@router.get("/api/v1/system/update/status")
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

@router.get("/api/v1/system/update/log")
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


# ----------------- Debian / Ubuntu OS Package Manager -----------------

OS_PACKAGES_CACHE = Path("/var/lib/zclockid/upgradable_packages.json")

def parse_upgradable_packages(raw_stdout: str):
    packages = []
    security_count = 0
    for line in raw_stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Listing"):
            continue
        m = re.match(r"^([^/\s]+)/([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+\[upgradable from:\s*([^\]]+)\]", line)
        if m:
            pkg_name = m.group(1)
            suite = m.group(2)
            cand_ver = m.group(3)
            arch = m.group(4)
            curr_ver = m.group(5)
            is_sec = "security" in suite.lower()
            if is_sec:
                security_count += 1

            cat = "General"
            if any(pkg_name.startswith(p) for p in ["linux-image", "linux-headers", "linux-generic", "linux-modules", "linux-tools"]):
                cat = "Kernel"
            elif any(pkg_name.startswith(p) for p in ["openssl", "libssl", "ca-certificates", "gnutls", "krb5"]):
                cat = "Security / Crypto"
            elif any(pkg_name.startswith(p) for p in ["systemd", "udev", "netplan", "init", "base-files", "libc", "apparmor"]):
                cat = "Core System"
            elif any(pkg_name.startswith(p) for p in ["samba", "winbind", "bind9", "freeradius"]):
                cat = "Directory / DNS"
            elif any(pkg_name.startswith(p) for p in ["python"]):
                cat = "Python Runtime"

            packages.append({
                "name": pkg_name,
                "suite": suite,
                "candidate_version": cand_ver,
                "current_version": curr_ver,
                "arch": arch,
                "is_security": is_sec,
                "category": cat
            })
    return packages, security_count

@router.get("/api/v1/system/os-updates/info")
def get_os_update_info():
    """Returns cached list of upgradable system packages and background upgrade state."""
    status_file = Path("/var/run/zclock-os-update.status")
    last_status = status_file.read_text().strip() if status_file.exists() else "IDLE"

    code, stdout, _ = run_cmd(["pgrep", "-f", "zclock-os-updater.sh|apt-get|dpkg"])
    is_running = (code == 0 and len(stdout.strip()) > 0)

    reboot_file = Path("/var/run/reboot-required")
    reboot_required = reboot_file.exists()
    reboot_pkgs = []
    reboot_pkgs_file = Path("/var/run/reboot-required.pkgs")
    if reboot_pkgs_file.exists():
        try:
            reboot_pkgs = [p.strip() for p in reboot_pkgs_file.read_text().splitlines() if p.strip()]
        except Exception:
            pass

    cached_data = {}
    if OS_PACKAGES_CACHE.exists():
        try:
            cached_data = json.loads(OS_PACKAGES_CACHE.read_text())
        except Exception:
            cached_data = {}

    packages = cached_data.get("packages", [])
    total_upgrades = cached_data.get("total_upgrades", len(packages))
    security_upgrades = cached_data.get("security_upgrades", 0)
    last_checked = cached_data.get("last_checked", 0)

    return {
        "is_running": is_running,
        "last_status": last_status,
        "reboot_required": reboot_required,
        "reboot_packages": reboot_pkgs,
        "total_upgrades": total_upgrades,
        "security_upgrades": security_upgrades,
        "last_checked": last_checked,
        "packages": packages
    }

@router.post("/api/v1/system/os-updates/check")
def check_os_updates():
    """Refreshes APT cache and queries for all upgradable Debian / Ubuntu OS packages."""
    code, stdout, _ = run_cmd(["pgrep", "-f", "zclock-os-updater.sh|apt-get|dpkg"])
    if code == 0 and len(stdout.strip()) > 0:
        raise HTTPException(status_code=409, detail="A package management or update task is currently running.")

    run_cmd(["apt-get", "update"])

    code, stdout, stderr = run_cmd(["apt", "list", "--upgradable"])
    if code != 0:
        code, stdout, stderr = run_cmd(["apt-get", "-s", "dist-upgrade"])

    packages, security_count = parse_upgradable_packages(stdout)
    now = time.time()

    cache_payload = {
        "status": "success",
        "total_upgrades": len(packages),
        "security_upgrades": security_count,
        "packages": packages,
        "last_checked": now
    }

    try:
        OS_PACKAGES_CACHE.parent.mkdir(parents=True, exist_ok=True)
        OS_PACKAGES_CACHE.write_text(json.dumps(cache_payload, indent=2))
    except Exception:
        pass

    log_audit("OS_UPDATES_CHECKED", "admin", "apt", "SUCCESS", {"total": len(packages), "security": security_count})
    return cache_payload

@router.post("/api/v1/system/os-updates/upgrade")
def trigger_os_upgrade():
    """Initiates background non-interactive Debian / Ubuntu OS package upgrade."""
    code, stdout, _ = run_cmd(["pgrep", "-f", "zclock-os-updater.sh|apt-get|dpkg"])
    if code == 0 and len(stdout.strip()) > 0:
        raise HTTPException(status_code=409, detail="A package management or upgrade operation is already running.")

    updater_script = ensure_os_updater_script()
    launch_os_update_runner(updater_script, "all")
    log_audit("OS_UPGRADE_STARTED", "admin", "apt", "STARTED", {})

    return {
        "status": "started",
        "message": "Debian/Ubuntu system package upgrade initiated in background. You can monitor the terminal log below."
    }

@router.get("/api/v1/system/os-updates/log")
def get_os_update_log():
    """Returns the live output log from /var/log/zclock-os-update.log."""
    log_file = Path("/var/log/zclock-os-update.log")
    if not log_file.exists():
        return {"log": "No system update log found. No upgrades have been executed yet.", "lines": []}
    content = log_file.read_text()
    return {
        "log": content,
        "lines": content.splitlines()[-150:],
        "size": len(content)
    }


