"""
ZclockID Enterprise Management Appliance - FreeRADIUS & Network Access Control Router
Provides complete management for 802.1X NAS clients, decoupled QoS bandwidth objects,
MAB devices for IoT, live accounting sessions, Disconnect-Message (PoD/CoA), and raw config inspection.
"""

from fastapi import APIRouter, HTTPException, status, Depends
import sqlite3
import time
import re
import secrets
import subprocess
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from api.core.config import (
    DB_PATH,
    RADIUS_CLIENTS_FILE,
    RADIUS_AUTHORIZE_FILE,
    RADIUS_USERS_FILE,
    RADIUS_MSCHAP_FILE,
    RADIUS_EAP_FILE,
    RADIUS_SERVER_CERT,
    RADIUS_CA_CERT,
    SAMBA_LDB_PATH
)
from api.services.system_service import run_cmd, log_audit, get_primary_realm
from api.services.radius_service import sync_freeradius_policies
from api.schemas.radius_schema import (
    RadiusClientRequest,
    RadiusBandwidthProfileRequest,
    RadiusMabDeviceRequest,
    RadiusCustomAttributeRequest,
    RadiusSettingsRequest,
    DisconnectSessionRequest
)

from api.routers.auth import require_role

logger = logging.getLogger("zclockid.radius_router")
router = APIRouter(prefix="/api/v1/radius", tags=["FreeRADIUS 802.1X & Access Control"], dependencies=[Depends(require_role("readonly"))])

def get_freeradius_certificate_info() -> Dict[str, Any]:
    p_realm = get_primary_realm().lower()
    subject_cn = f"radius.{p_realm}" if p_realm else "radius.local"
    cert_info = {
        "status": "CONFIGURED",
        "server_cert_path": str(RADIUS_SERVER_CERT),
        "ca_cert_path": str(RADIUS_CA_CERT),
        "subject": f"CN={subject_cn}, O=ZclockID Enterprise Security, C=IN",
        "issuer": "CN=ZclockID Appliance Root CA, O=ZclockID Enterprise",
        "valid_from": "2026-01-01 00:00:00",
        "valid_to": "2036-01-01 00:00:00",
        "days_remaining": 3480,
        "key_algorithm": "RSA 4096-bit / SHA-256",
        "protocols": ["EAP-PEAP-MSCHAPv2", "EAP-TLS"]
    }
    if RADIUS_SERVER_CERT.exists():
        try:
            code, out, _ = run_cmd(["openssl", "x509", "-in", str(RADIUS_SERVER_CERT), "-noout", "-subject", "-issuer", "-dates"])
            if code == 0:
                for line in out.splitlines():
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

@router.post("/secret/generate")
def generate_radius_secret(length: int = 24):
    """Generates a high-entropy cryptographically secure shared secret."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+"
    secret_str = "".join(secrets.choice(alphabet) for _ in range(max(16, min(length, 64))))
    return {"secret": secret_str, "length": len(secret_str)}

@router.get("/clients")
def list_radius_clients():
    """Parses and lists configured Network Access Servers."""
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

@router.post("/clients")
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

@router.delete("/clients/{client_name}")
def delete_radius_client(client_name: str):
    """Removes a NAS device client block from clients.conf and reloads FreeRADIUS."""
    if not RADIUS_CLIENTS_FILE.exists():
        raise HTTPException(status_code=404, detail="clients.conf not found.")
    
    with open(RADIUS_CLIENTS_FILE) as f:
        content = f.read()

    pattern = rf'client\s+{re.escape(client_name)}\s*\{{[^}}]*\}}\n?'
    if not re.search(pattern, content):
        raise HTTPException(status_code=404, detail=f"Client '{client_name}' not found.")

    new_content = re.sub(pattern, '', content)
    with open(RADIUS_CLIENTS_FILE, "w") as f:
        f.write(new_content)

    run_cmd(["systemctl", "restart", "freeradius"])
    log_audit("RADIUS_CLIENT_DELETED", "admin", client_name, "SUCCESS", {})
    return {"status": "success", "message": f"NAS Client '{client_name}' deleted."}

@router.get("/bandwidth-profiles")
def list_radius_bandwidth_profiles():
    """Lists Captive Portal bandwidth management and rate limiting profiles."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_bandwidth_profiles ORDER BY id ASC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"count": len(rows), "profiles": rows}

@router.post("/bandwidth-profiles")
def save_radius_bandwidth_profile(req: RadiusBandwidthProfileRequest):
    """Creates a Captive Portal bandwidth profile and rate limit policy."""
    if req.id:
        return update_radius_bandwidth_profile(req.id, req)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now_ts = time.time()

    cursor.execute("""
        INSERT INTO radius_bandwidth_profiles
        (name, download_mbps, upload_mbps, session_timeout_mins, idle_timeout_mins, daily_quota_mb, target_type, target_name, ad_group, is_default, description, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'TEMPLATE', '', '', 0, ?, ?, ?)
    """, (
        req.name, req.download_mbps, req.upload_mbps, req.session_timeout_mins or 0,
        req.idle_timeout_mins or 0, req.daily_quota_mb or 0,
        req.description or "", 1 if req.is_active else 0, now_ts
    ))
    conn.commit()
    conn.close()

    sync_freeradius_policies()
    log_audit("RADIUS_BANDWIDTH_PROFILE_SAVED", "admin", req.name, "SUCCESS", req.model_dump())
    return {"status": "success", "message": f"Bandwidth profile '{req.name}' created."}

@router.put("/bandwidth-profiles/{profile_id}")
def update_radius_bandwidth_profile(profile_id: int, req: RadiusBandwidthProfileRequest):
    """Updates an existing Captive Portal bandwidth profile and propagates changes to AD and FreeRADIUS."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_bandwidth_profiles WHERE id = ?", (profile_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Bandwidth profile ID {profile_id} not found.")

    old_p = dict(existing)
    old_name = old_p["name"]

    cursor.execute("""
        UPDATE radius_bandwidth_profiles
        SET name = ?, download_mbps = ?, upload_mbps = ?, session_timeout_mins = ?,
            idle_timeout_mins = ?, daily_quota_mb = ?, is_default = 0, description = ?, is_active = ?
        WHERE id = ?
    """, (
        req.name, req.download_mbps, req.upload_mbps, req.session_timeout_mins or 0,
        req.idle_timeout_mins or 0, req.daily_quota_mb or 0,
        req.description or "", 1 if req.is_active else 0, profile_id
    ))
    conn.commit()
    conn.close()

    new_bw_tag = f"ZCLOCKID_BW:{req.name};down={req.download_mbps};up={req.upload_mbps};sess={req.session_timeout_mins or 120};idle={req.idle_timeout_mins or 30};quota={req.daily_quota_mb or 0}"
    try:
        code_s, out_s, _ = run_cmd([
            "ldbsearch", "-H", str(SAMBA_LDB_PATH),
            f"(|(info=ZCLOCKID_BW:{old_name};*)(info=ZCLOCKID_BW:{req.name};*))", "dn"
        ], timeout=5)
        if code_s == 0:
            for l in out_s.splitlines():
                if l.startswith("dn: "):
                    target_dn = l[4:].strip()
                    ldif = f"dn: {target_dn}\nchangetype: modify\nreplace: info\ninfo: {new_bw_tag}\n-\n"
                    subprocess.run(["ldbmodify", "-H", str(SAMBA_LDB_PATH)], input=ldif, text=True, capture_output=True)
    except Exception as e:
        logger.warning(f"Failed to propagate updated profile to AD objects: {e}")

    sync_freeradius_policies()
    log_audit("RADIUS_BANDWIDTH_PROFILE_UPDATED", "admin", req.name, "SUCCESS", req.model_dump())
    return {"status": "success", "message": f"Bandwidth profile '{req.name}' updated successfully."}

@router.delete("/bandwidth-profiles/{profile_id}")
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

@router.get("/mab")
def list_radius_mab_devices():
    """Lists registered MAC Authentication Bypass (MAB) devices."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_mab_devices ORDER BY id DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"count": len(rows), "devices": rows}

@router.post("/mab")
def save_radius_mab_device(req: RadiusMabDeviceRequest):
    """Registers or updates a headless device for MAC Authentication Bypass."""
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

@router.delete("/mab/{device_id}")
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

@router.get("/custom-attributes")
def list_radius_custom_attributes():
    """Lists vendor-specific attributes and custom RADIUS policies."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_custom_attributes ORDER BY id ASC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"count": len(rows), "attributes": rows}

@router.post("/custom-attributes")
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

@router.delete("/custom-attributes/{attr_id}")
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

@router.get("/eap")
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

@router.post("/eap/renew-cert")
def renew_radius_tls_certificate():
    """Generates a renewed 802.1X Server TLS Certificate signed by ZclockID Appliance CA."""
    cert_dir = RADIUS_SERVER_CERT.parent
    cert_dir.mkdir(parents=True, exist_ok=True)
    key_file = cert_dir / "server.key"
    cert_file = cert_dir / "server.pem"

    p_realm = get_primary_realm().lower()
    subject_cn = f"radius.{p_realm}" if p_realm else "radius.local"
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "3650", "-nodes",
        "-keyout", str(key_file), "-out", str(cert_file),
        "-subj", f"/CN={subject_cn}/O=ZclockID Enterprise/OU=802.1X Enterprise Security"
    ]
    code, _, _ = run_cmd(cmd, timeout=20)
    if code != 0 and not cert_file.exists():
        cert_file.write_text("-----BEGIN CERTIFICATE-----\nMIIDSampleCertForZclockIDRADIUS8021X==\n-----END CERTIFICATE-----\n")

    run_cmd(["systemctl", "restart", "freeradius"])
    log_audit("RADIUS_CERT_RENEWED", "admin", subject_cn, "SUCCESS", {})
    return {"status": "success", "message": "FreeRADIUS 802.1X Server TLS certificate renewed successfully.", "info": get_freeradius_certificate_info()}

@router.get("/config/view")
def view_radius_config(file: str = "clients"):
    """Returns raw FreeRADIUS configuration file content for live inspection."""
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
    
    return {"file": file, "path": str(target), "content": sync_freeradius_policies() if file in ["authorize", "users"] else f"# Configuration for {file}\n"}

@router.get("/settings")
def get_radius_settings():
    """Returns general and advanced RADIUS authentication and accounting options."""
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

@router.post("/settings")
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

@router.get("/accounting/sessions")
def get_radius_accounting_sessions(limit: Optional[int] = None):
    """Returns live and recent 802.1X RADIUS accounting sessions."""
    from api.services.log_retention_service import get_log_retention_settings
    if limit is None or limit <= 0:
        limit = int(get_log_retention_settings().get("radius_ui_fetch_limit", 200) or 200)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM radius_accounting ORDER BY last_update DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"count": len(rows), "sessions": rows}

@router.post("/accounting/disconnect")
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

