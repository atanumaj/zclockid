"""
ZclockID Appliance System Security & Network Baseline Service
Enforces idle timeouts, CIDR IP filtering across Web GUI/API, OpenSSH hardening, and SNMP access controls.
"""

import os
import re
import time
import ipaddress
import sqlite3
from pathlib import Path
from typing import Tuple, List, Optional, Dict, Any
from fastapi import Request

from api.core.config import DB_PATH
from api.services.system_service import run_cmd, log_audit

def get_client_ip(request: Request) -> str:
    """Extracts client IP address considering reverse proxies (Nginx) and direct connections."""
    # Check X-Real-IP first
    x_real = request.headers.get("x-real-ip")
    if x_real:
        ip = x_real.strip()
    else:
        # Check X-Forwarded-For
        x_fwd = request.headers.get("x-forwarded-for")
        if x_fwd:
            ip = x_fwd.split(",")[0].strip()
        elif request.client and request.client.host:
            ip = request.client.host.strip()
        else:
            ip = "127.0.0.1"

    # Normalize IPv6-mapped IPv4 (e.g. ::ffff:192.168.1.100)
    if ip.startswith("::ffff:"):
        ip = ip.replace("::ffff:", "")
    return ip

def validate_subnets_syntax(subnets_str: str) -> Tuple[bool, str]:
    """Validates comma-separated CIDR subnets."""
    if not subnets_str or not subnets_str.strip():
        return True, ""
    tokens = [t.strip() for t in subnets_str.split(",") if t.strip()]
    for t in tokens:
        if t in ("*", "all", "0.0.0.0/0", "::/0"):
            continue
        try:
            ipaddress.ip_network(t, strict=False)
        except ValueError as e:
            return False, f"Invalid CIDR network '{t}': {str(e)}"
    return True, ""

def is_ip_allowed(client_ip: str, allowed_subnets_str: str) -> bool:
    """Checks if a client IP is allowed within configured subnets."""
    if not client_ip:
        return False
    if client_ip in ("127.0.0.1", "::1", "localhost"):
        return True
    if not allowed_subnets_str or not allowed_subnets_str.strip():
        return True

    # Normalize client IP
    if client_ip.startswith("::ffff:"):
        client_ip = client_ip.replace("::ffff:", "")

    try:
        client_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    tokens = [t.strip() for t in allowed_subnets_str.split(",") if t.strip()]
    for t in tokens:
        if t in ("*", "all", "0.0.0.0/0", "::/0"):
            return True
        try:
            net = ipaddress.ip_network(t, strict=False)
            if client_obj.version == net.version and client_obj in net:
                return True
        except ValueError:
            continue

    return False

def get_security_settings() -> Dict[str, Any]:
    """Fetches system-wide security settings from SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {
        "session_idle_timeout_min": 15,
        "session_max_lifetime_hours": 8,
        "allowed_subnets_gui": "0.0.0.0/0, ::/0",
        "allowed_subnets_ssh": "0.0.0.0/0, ::/0",
        "allowed_subnets_snmp": "192.168.1.0/24, 10.10.0.0/24, 127.0.0.1/32",
        "snmp_community": "zclock_public",
        "max_failed_logins": 5,
        "lockout_duration_min": 15,
        "ssh_permit_root": 0,
        "ssh_password_auth": 1,
        "updated_at": time.time()
    }

def apply_ssh_hardening(allowed_subnets: str, permit_root: int, password_auth: int) -> Tuple[bool, str]:
    """
    Applies OpenSSH security baseline to /etc/ssh/sshd_config.d/99-zclockid-security.conf.
    Validates syntax before reloading ssh daemon to ensure zero administrative lockout.
    """
    config_dir = Path("/etc/ssh/sshd_config.d")
    config_dir.mkdir(parents=True, exist_ok=True)
    target_file = config_dir / "99-zclockid-security.conf"
    temp_file = config_dir / "99-zclockid-security.conf.tmp"

    lines = [
        "# ZclockID Appliance Automated SSH Security Baseline",
        f"PermitRootLogin {'yes' if permit_root == 1 else 'no'}",
        f"PasswordAuthentication {'yes' if password_auth == 1 else 'no'}",
        "X11Forwarding no",
        "MaxAuthTries 5",
        "ClientAliveInterval 300",
        "ClientAliveCountMax 2",
    ]

    # Subnet CIDR ACL
    clean_subnets = [s.strip() for s in allowed_subnets.split(",") if s.strip()]
    is_open = any(s in ("0.0.0.0/0", "::/0", "*", "all") for s in clean_subnets) or not clean_subnets

    if not is_open:
        # Construct Match Address exclusion rule: deny everyone NOT in allowed subnets
        exclusions = []
        for s in clean_subnets:
            exclusions.append(f"!{s}")
        # Always include loopback in allowed
        exclusions.append("!127.0.0.1")
        exclusions.append("!::1")
        match_pattern = f"*,{','.join(exclusions)}"
        lines.append("")
        lines.append(f"Match Address {match_pattern}")
        lines.append("    DenyUsers *")

    content = "\n".join(lines) + "\n"

    try:
        with open(temp_file, "w") as f:
            f.write(content)

        # Test configuration syntax with sshd -t
        code, stdout, stderr = run_cmd(["sshd", "-t"], timeout=10)
        if code != 0:
            if temp_file.exists():
                temp_file.unlink()
            return False, f"sshd config verification failed: {stderr or stdout}"

        # Replace live config
        temp_file.replace(target_file)
        os.chmod(target_file, 0o600)

        # Reload ssh
        run_cmd(["systemctl", "reload", "ssh"], timeout=10)
        return True, "OpenSSH baseline and CIDR ACL applied successfully."
    except Exception as e:
        if temp_file.exists():
            temp_file.unlink()
        return False, str(e)

def apply_snmp_hardening(allowed_subnets: str, community: str) -> Tuple[bool, str]:
    """
    Applies SNMP access restrictions to /etc/snmp/snmpd.conf.
    Configures rocommunity per authorized CIDR block.
    """
    snmp_conf = Path("/etc/snmp/snmpd.conf")
    if not snmp_conf.exists():
        return True, "SNMP configuration not present."

    try:
        with open(snmp_conf, "r") as f:
            content = f.read()

        # Remove existing rocommunity lines
        new_lines = []
        for line in content.splitlines():
            if line.strip().startswith("rocommunity "):
                continue
            new_lines.append(line)

        clean_subnets = [s.strip() for s in allowed_subnets.split(",") if s.strip()]
        is_open = any(s in ("0.0.0.0/0", "::/0", "*", "all") for s in clean_subnets) or not clean_subnets

        new_lines.append(f"# ZclockID Managed SNMP Access Rules")
        if is_open:
            new_lines.append(f"rocommunity {community} default")
        else:
            for s in clean_subnets:
                new_lines.append(f"rocommunity {community} {s}")
            new_lines.append(f"rocommunity {community} 127.0.0.1")

        with open(snmp_conf, "w") as f:
            f.write("\n".join(new_lines) + "\n")

        run_cmd(["systemctl", "reload-or-restart", "snmpd"], timeout=10)
        return True, "SNMP access control and community updated successfully."
    except Exception as e:
        return False, str(e)
