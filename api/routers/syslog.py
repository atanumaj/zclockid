"""
ZclockID Remote Syslog & Log Streaming Engine
Supports RFC5424 / RFC3164 remote forwarding configuration and categorized live log streaming.
"""

import time
import socket
import sqlite3
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from api.core.config import DB_PATH
from api.services.system_service import log_audit, run_cmd
from api.services.log_retention_service import (
    get_log_retention_settings,
    update_log_retention_settings,
    get_log_table_counts,
    prune_logs_by_policy,
)
from api.schemas.syslog_schema import (
    SyslogConfigRequest,
    SyslogTestEventRequest
)

router = APIRouter(prefix="/api/v1/syslog", tags=["Syslog & Live Logs"])

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def format_rfc5424(facility_code: int, severity: int, app_name: str, msg: str) -> str:
    """Formats a message according to RFC 5424."""
    pri = (facility_code * 8) + severity
    hostname = socket.gethostname()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return f"<{pri}>1 {timestamp} {hostname} {app_name} - - - {msg}\n"

def format_rfc3164(facility_code: int, severity: int, app_name: str, msg: str) -> str:
    """Formats a message according to RFC 3164 (BSD syslog)."""
    pri = (facility_code * 8) + severity
    timestamp = time.strftime("%b %d %H:%M:%S", time.localtime())
    return f"<{pri}>{timestamp} {socket.gethostname()} {app_name}: {msg}\n"

FACILITY_MAP = {
    "auth": 4,
    "daemon": 3,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
    "user": 1
}

@router.get("/settings")
def get_syslog_settings():
    """Retrieves current remote Syslog forwarder configuration."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM syslog_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {
            "enabled": False,
            "remote_host": "",
            "remote_port": 514,
            "protocol": "UDP",
            "facility": "local0",
            "log_format": "RFC5424",
            "send_samba_logs": True,
            "send_radius_logs": True,
            "send_auth_logs": True,
            "send_system_logs": True
        }

    return {
        "enabled": bool(row["enabled"]),
        "remote_host": row["remote_host"] or "",
        "remote_port": row["remote_port"] or 514,
        "protocol": row["protocol"] or "UDP",
        "facility": row["facility"] or "local0",
        "log_format": row["log_format"] or "RFC5424",
        "send_samba_logs": bool(row["send_samba_logs"]),
        "send_radius_logs": bool(row["send_radius_logs"]),
        "send_auth_logs": bool(row["send_auth_logs"]),
        "send_system_logs": bool(row["send_system_logs"]),
        "updated_at": row["updated_at"]
    }

@router.put("/settings")
def update_syslog_settings(req: SyslogConfigRequest):
    """Updates the remote Syslog forwarding configuration."""
    conn = get_db()
    cursor = conn.cursor()
    now = time.time()
    cursor.execute("""
        INSERT INTO syslog_settings (
            id, enabled, remote_host, remote_port, protocol, facility, log_format,
            send_samba_logs, send_radius_logs, send_auth_logs, send_system_logs, updated_at
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            enabled=excluded.enabled,
            remote_host=excluded.remote_host,
            remote_port=excluded.remote_port,
            protocol=excluded.protocol,
            facility=excluded.facility,
            log_format=excluded.log_format,
            send_samba_logs=excluded.send_samba_logs,
            send_radius_logs=excluded.send_radius_logs,
            send_auth_logs=excluded.send_auth_logs,
            send_system_logs=excluded.send_system_logs,
            updated_at=excluded.updated_at
    """, (
        1 if req.enabled else 0,
        req.remote_host.strip(),
        req.remote_port,
        req.protocol.upper(),
        req.facility.lower(),
        req.log_format.upper(),
        1 if req.send_samba_logs else 0,
        1 if req.send_radius_logs else 0,
        1 if req.send_auth_logs else 0,
        1 if req.send_system_logs else 0,
        now
    ))
    conn.commit()
    conn.close()

    log_audit("SYSLOG_SETTINGS_UPDATED", "admin", req.remote_host, "SUCCESS", {
        "enabled": req.enabled,
        "port": req.remote_port,
        "protocol": req.protocol
    })

    return {"status": "success", "message": "Syslog forwarder configuration updated successfully."}

@router.post("/test")
def send_syslog_test_probe(req: SyslogTestEventRequest):
    """Sends a live test probe message to the configured remote Syslog collector."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM syslog_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    if not row or not row["remote_host"]:
        raise HTTPException(status_code=400, detail="No remote syslog host configured. Please specify a target IP or hostname first.")

    host = row["remote_host"].strip()
    port = int(row["remote_port"])
    proto = (row["protocol"] or "UDP").upper()
    facility = (row["facility"] or "local0").lower()
    fmt = (row["log_format"] or "RFC5424").upper()

    fac_code = FACILITY_MAP.get(facility, 16)
    # Severity 6 = Informational
    msg_body = req.message or "ZclockID Syslog Test Probe Event"
    if fmt == "RFC3164":
        packet_str = format_rfc3164(fac_code, 6, "zclock-probe", msg_body)
    else:
        packet_str = format_rfc5424(fac_code, 6, "zclock-probe", msg_body)

    packet_bytes = packet_str.encode("utf-8")

    try:
        if proto == "TCP":
            with socket.create_connection((host, port), timeout=4) as sock:
                sock.sendall(packet_bytes)
        elif proto == "TLS":
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=4) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    tls_sock.sendall(packet_bytes)
        else: # UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(packet_bytes, (host, port))
            sock.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to transmit syslog probe to {host}:{port} ({proto}): {str(e)}")

    log_audit("SYSLOG_TEST_PROBE_SENT", "admin", f"{host}:{port}", "SUCCESS", {"protocol": proto})
    return {
        "status": "success",
        "message": f"Syslog probe successfully transmitted to {host}:{port} via {proto} ({fmt}).",
        "packet": packet_str.strip()
    }

@router.get("/logs")
def get_categorized_logs(
    category: str = Query("system", pattern="^(samba|radius|auth|audit|system)$"),
    lines: int = Query(100, ge=10, le=5000),
    filter: Optional[str] = Query(None)
):
    """
    Retrieves live categorized system and daemon logs with real-time text filtering.
    Categories: samba (AD DC), radius (FreeRADIUS), auth (SSHD/PAM), audit (ZclockID Audit DB), system (journal).
    """
    ret_settings = get_log_retention_settings()
    max_allowed = max(10, min(5000, int(ret_settings.get("live_log_max_lines", 1000) or 1000)))
    lines = min(lines, max_allowed)
    logs = []

    if category == "audit":
        conn = get_db()
        cursor = conn.cursor()
        query = "SELECT id, event_type, actor, target, status, details, timestamp FROM audit_events"
        params = []
        if filter:
            query += " WHERE event_type LIKE ? OR actor LIKE ? OR target LIKE ? OR details LIKE ?"
            f_arg = f"%{filter}%"
            params.extend([f_arg, f_arg, f_arg, f_arg])
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(lines)
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        conn.close()

        for r in rows:
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["timestamp"]))
            logs.append({
                "timestamp": ts_str,
                "unit": "zclock-audit",
                "level": "INFO" if r["status"] == "SUCCESS" else "WARN",
                "message": f"[{r['event_type']}] actor={r['actor']} target={r['target']} status={r['status']} details={r['details']}"
            })
        return {"category": category, "count": len(logs), "logs": logs}

    # Journalctl based categories
    unit_map = {
        "samba": ["-u", "samba-ad-dc"],
        "radius": ["-u", "freeradius"],
        "auth": ["-u", "ssh", "-u", "sshd"],
        "system": []
    }

    cmd = ["journalctl"] + unit_map.get(category, []) + ["-n", str(lines), "--no-pager"]
    code, stdout, stderr = run_cmd(cmd, timeout=6)
    if code != 0 and not stdout:
        return {"category": category, "count": 0, "logs": [], "error": stderr}

    filter_lower = filter.lower() if filter else None
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if filter_lower and filter_lower not in line.lower():
            continue

        parts = line.split(" ", 3)
        if len(parts) >= 4:
            ts = f"{parts[0]} {parts[1]} {parts[2]}"
            rest = parts[3]
        else:
            ts = ""
            rest = line

        # Level inference
        level = "INFO"
        upper_rest = rest.upper()
        if "ERROR" in upper_rest or "FAIL" in upper_rest or "DENIED" in upper_rest:
            level = "ERROR"
        elif "WARN" in upper_rest or "WARNING" in upper_rest:
            level = "WARN"

        logs.append({
            "timestamp": ts,
            "unit": category,
            "level": level,
            "message": rest
        })

    return {"category": category, "count": len(logs), "logs": logs}


class LogRetentionUpdateRequest(BaseModel):
    audit_retention_days: int = Field(180, ge=0, le=3650)
    audit_max_entries: int = Field(50000, ge=0, le=5000000)
    audit_ui_fetch_limit: int = Field(500, ge=50, le=10000)
    self_service_retention_days: int = Field(180, ge=0, le=3650)
    self_service_max_entries: int = Field(10000, ge=0, le=1000000)
    self_service_ui_fetch_limit: int = Field(500, ge=50, le=10000)
    live_log_default_lines: int = Field(100, ge=10, le=5000)
    live_log_max_lines: int = Field(1000, ge=50, le=5000)
    radius_retention_days: int = Field(180, ge=0, le=3650)
    radius_max_entries: int = Field(50000, ge=0, le=5000000)
    radius_ui_fetch_limit: int = Field(200, ge=25, le=10000)
    auto_prune_enabled: bool = True


@router.get("/retention")
def get_retention_policy():
    """Returns configured log retention periods, query/display limits, and live table row counts."""
    settings = get_log_retention_settings()
    counts = get_log_table_counts()
    return {
        "status": "success",
        "settings": settings,
        "counts": counts,
    }


@router.put("/retention")
def update_retention_policy(req: LogRetentionUpdateRequest):
    """Updates log retention periods and query/display limits across all logging subsystems."""
    payload = req.model_dump()
    payload["auto_prune_enabled"] = 1 if req.auto_prune_enabled else 0
    if payload["live_log_default_lines"] > payload["live_log_max_lines"]:
        payload["live_log_default_lines"] = payload["live_log_max_lines"]
    updated = update_log_retention_settings(payload)
    log_audit("LOG_RETENTION_UPDATED", "admin", "log_retention_settings", "SUCCESS", payload)
    return {
        "status": "success",
        "message": "Log retention & query limit policies updated successfully.",
        "settings": updated,
        "counts": get_log_table_counts(),
    }


@router.post("/retention/prune")
def run_retention_prune_now():
    """Immediately executes log retention cleanup according to configured age and entry limits."""
    result = prune_logs_by_policy(force=True)
    log_audit("LOG_RETENTION_PRUNED", "admin", "all_log_tables", "SUCCESS", result.get("deleted", {}))
    return {
        "status": "success",
        "message": f"Retention cleanup completed. Removed {result.get('total_deleted', 0)} expired/excess log entries.",
        **result,
    }
