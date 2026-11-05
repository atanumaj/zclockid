"""
ZclockID Enterprise Management Appliance - System Supervisor & Native OS Service
Provides non-blocking process execution, systemd introspection, audit logging, and version detection.
"""

import subprocess
import os
import re
import json
import time
from typing import List, Tuple, Dict, Any, Optional
from pathlib import Path
from api.core.config import SMB_CONF_FILE, DEFAULT_REALM
from api.db.init_db import get_db_connection

def run_cmd(cmd: List[str], timeout: int = 45) -> Tuple[int, str, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout, res.stderr
    except FileNotFoundError:
        return -1, "", f"Command '{cmd[0]}' not installed"
    except Exception as e:
        return -1, "", str(e)

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
        conn = get_db_connection()
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
    if SMB_CONF_FILE.exists():
        try:
            for line in SMB_CONF_FILE.read_text().splitlines():
                line = line.strip()
                if line.lower().startswith("realm") and "=" in line:
                    return line.split("=", 1)[1].strip()
        except Exception:
            pass
    return DEFAULT_REALM

def get_appliance_version() -> str:
    ver_file = Path("/zclockid/VERSION") if Path("/zclockid/VERSION").exists() else Path("/opt/zclockid/VERSION")
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
    return "2.0.0"

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
