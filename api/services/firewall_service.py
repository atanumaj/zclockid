"""
ZclockID Appliance Host Firewall Service
Manages Linux Netfilter/UFW firewall rules, default drop policies, and custom port access control.
"""

import time
import ipaddress
import sqlite3
import re
from typing import Dict, List, Optional, Tuple, Any

from api.core.config import DB_PATH
from api.services.system_service import run_cmd, log_audit

def normalize_port(port_str: str) -> str:
    """Validates and normalizes port number or range (e.g. '80', '3000-3005', '49152:65535')."""
    port_str = port_str.strip().replace(" ", "").replace("-", ":")
    if ":" in port_str:
        parts = port_str.split(":")
        if len(parts) != 2:
            raise ValueError(f"Invalid port range '{port_str}'. Expected format like '3000-3005' or '8080'.")
        p1, p2 = int(parts[0]), int(parts[1])
        if not (1 <= p1 <= 65535 and 1 <= p2 <= 65535 and p1 < p2):
            raise ValueError(f"Port range '{port_str}' must be between 1 and 65535 in ascending order.")
        return f"{p1}:{p2}"
    else:
        p = int(port_str)
        if not (1 <= p <= 65535):
            raise ValueError(f"Port number {p} must be between 1 and 65535.")
        return str(p)

def normalize_source(source_str: str) -> str:
    """Validates and normalizes source IP, CIDR subnet, or comma-separated list of IPs/CIDRs."""
    if not source_str or not source_str.strip():
        return "Any"
    parts = [p.strip() for p in source_str.split(",") if p.strip()]
    if not parts or any(p.lower() in ("any", "all", "0.0.0.0/0", "::/0", "*") for p in parts):
        return "Any"
    valid_cidrs = []
    for item in parts:
        try:
            net = ipaddress.ip_network(item, strict=False)
            valid_cidrs.append(str(net))
        except ValueError as e:
            raise ValueError(f"Invalid source IP or CIDR network '{item}': {str(e)}")
    return ", ".join(valid_cidrs)

DEFAULT_FIREWALL_RULES = [
    ("ALLOW", "TCP", "22", "Any", "Administrative SSH Access"),
    ("ALLOW", "TCP", "443", "Any", "Web Console HTTPS Access"),
    ("ALLOW", "TCP", "80", "Any", "Web Console HTTP Redirect"),
    ("ALLOW", "BOTH", "53", "Any", "DNS Server (BIND9 DLZ / DoH)"),
    ("ALLOW", "BOTH", "88", "Any", "Active Directory Kerberos KDC"),
    ("ALLOW", "BOTH", "464", "Any", "Kerberos Password Change (kpasswd)"),
    ("ALLOW", "BOTH", "389", "Any", "Active Directory LDAP Directory Service"),
    ("ALLOW", "TCP", "636", "Any", "Active Directory Secure LDAP (LDAPS)"),
    ("ALLOW", "TCP", "3268", "Any", "Active Directory Global Catalog (GC)"),
    ("ALLOW", "TCP", "3269", "Any", "Active Directory Secure Global Catalog"),
    ("ALLOW", "TCP", "445", "Any", "Active Directory SMB & Sysvol Replication"),
    ("ALLOW", "TCP", "139", "Any", "NetBIOS Session Service"),
    ("ALLOW", "UDP", "137", "Any", "NetBIOS Name Service (NBNS)"),
    ("ALLOW", "UDP", "138", "Any", "NetBIOS Datagram Service"),
    ("ALLOW", "TCP", "135", "Any", "MS-RPC Endpoint Mapper"),
    ("ALLOW", "TCP", "49152:65535", "Any", "Active Directory RPC Dynamic Ports"),
    ("ALLOW", "UDP", "1812", "Any", "FreeRADIUS 802.1X Authentication"),
    ("ALLOW", "UDP", "1813", "Any", "FreeRADIUS Session Accounting"),
    ("ALLOW", "UDP", "123", "Any", "Chrony Enterprise NTP Server"),
    ("ALLOW", "UDP", "161", "Any", "Net-SNMP Appliance Telemetry"),
]

def is_ufw_installed() -> bool:
    code, _, _ = run_cmd(["which", "ufw"])
    return code == 0

def ensure_ufw_installed():
    if not is_ufw_installed():
        run_cmd(["apt-get", "update"])
        run_cmd(["apt-get", "install", "-y", "ufw"])

def get_live_ufw_status() -> str:
    if not is_ufw_installed():
        return "not_installed"
    code, stdout, _ = run_cmd(["ufw", "status"])
    if "Status: active" in stdout:
        return "active"
    return "inactive"

def get_firewall_status() -> Dict[str, Any]:
    """Returns stored firewall configuration, unified rules list, and live kernel enforcement status."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM firewall_settings WHERE id = 1")
    settings_row = cursor.fetchone()
    is_enabled = bool(settings_row["is_enabled"]) if settings_row else False
    def_in = settings_row["default_incoming"] if settings_row else "DENY"
    def_out = settings_row["default_outgoing"] if settings_row else "ALLOW"

    cursor.execute("SELECT * FROM firewall_rules ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()

    rules = []
    active_count = 0
    for r in rows:
        enabled = bool(r["is_enabled"])
        if enabled:
            active_count += 1
        rules.append({
            "id": r["id"],
            "rule_type": r["rule_type"],
            "action": r["action"],
            "protocol": r["protocol"],
            "port": r["port"],
            "source": r["source"],
            "comment": r["comment"] or "",
            "is_enabled": enabled,
            "created_at": r["created_at"],
            "updated_at": r["updated_at"]
        })

    live_status = get_live_ufw_status()

    return {
        "is_enabled": is_enabled,
        "live_status": live_status,
        "default_incoming": def_in,
        "default_outgoing": def_out,
        "total_rules_count": len(rules),
        "active_rules_count": active_count,
        "rules": rules
    }

def apply_firewall() -> Tuple[bool, str]:
    """Translates database rules to UFW and commits to the Linux kernel."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT is_enabled FROM firewall_settings WHERE id = 1")
    row = cursor.fetchone()
    is_enabled = bool(row["is_enabled"]) if row else False

    if not is_enabled:
        conn.close()
        if is_ufw_installed():
            run_cmd(["ufw", "--force", "disable"])
        log_audit("FIREWALL_DISABLED", "admin", "ufw", "SUCCESS", {})
        return True, "Firewall disabled. System is in unrestricted network mode."

    ensure_ufw_installed()

    # Read all active rules
    cursor.execute("SELECT * FROM firewall_rules WHERE is_enabled = 1")
    active_rules = cursor.fetchall()
    conn.close()

    # Reset and configure default drop policy
    run_cmd(["ufw", "--force", "reset"])
    run_cmd(["ufw", "default", "deny", "incoming"])
    run_cmd(["ufw", "default", "allow", "outgoing"])

    # Fallback safety: If active_rules is completely empty, prevent hard lockout on SSH
    if len(active_rules) == 0:
        run_cmd(["ufw", "allow", "22/tcp"])
        run_cmd(["ufw", "allow", "443/tcp"])

    # Apply database rules in order
    for r in active_rules:
        act = r["action"].lower()
        proto = r["protocol"].upper()
        clean_port = r["port"].replace("-", ":")
        src_str = r["source"].strip()

        protocols = ["tcp", "udp"] if proto == "BOTH" else [proto.lower()]
        if src_str.lower() in ("any", "0.0.0.0/0", "all", "*", ""):
            sources = ["Any"]
        else:
            sources = [s.strip() for s in src_str.split(",") if s.strip()]

        for p in protocols:
            for s in sources:
                if s.lower() in ("any", "0.0.0.0/0", "all", "*"):
                    run_cmd(["ufw", act, f"{clean_port}/{p}"])
                else:
                    run_cmd(["ufw", act, "from", s, "to", "any", "port", clean_port, "proto", p])

    code, stdout, stderr = run_cmd(["ufw", "--force", "enable"])
    if code != 0:
        log_audit("FIREWALL_APPLY_FAILED", "admin", "ufw", "FAILED", {"error": stderr})
        return False, f"Failed to activate firewall: {stderr}"

    log_audit("FIREWALL_APPLIED", "admin", "ufw", "SUCCESS", {"rules_applied": len(active_rules)})
    return True, f"Firewall activated successfully! Default incoming denied. {len(active_rules)} port rules enforced."

def reset_to_default_template() -> Tuple[bool, str]:
    """Wipes all current rules and resets to the recommended baseline template required for ZclockID functions."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM firewall_rules")
    now = time.time()
    for action, proto, port, src, comment in DEFAULT_FIREWALL_RULES:
        cursor.execute("""
            INSERT INTO firewall_rules (rule_type, action, protocol, port, source, comment, is_enabled, created_at, updated_at)
            VALUES ('standard', ?, ?, ?, ?, ?, 1, ?, ?)
        """, (action, proto, port, src, comment, now, now))
    conn.commit()
    conn.close()
    return apply_firewall()

def toggle_firewall_state(enable: bool) -> Tuple[bool, str]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE firewall_settings SET is_enabled = ?, updated_at = ? WHERE id = 1", (1 if enable else 0, time.time()))
    conn.commit()
    conn.close()
    return apply_firewall()

def add_custom_rule(action: str, protocol: str, port: str, source: str, comment: str, is_enabled: bool = True) -> int:
    action = action.upper().strip()
    if action not in ("ALLOW", "DENY"):
        raise ValueError("Rule action must be ALLOW or DENY.")

    protocol = protocol.upper().strip()
    if protocol not in ("TCP", "UDP", "BOTH"):
        raise ValueError("Rule protocol must be TCP, UDP, or BOTH.")

    norm_port = normalize_port(port)
    norm_source = normalize_source(source)
    now = time.time()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO firewall_rules (rule_type, action, protocol, port, source, comment, is_enabled, created_at, updated_at)
        VALUES ('rule', ?, ?, ?, ?, ?, ?, ?, ?)
    """, (action, protocol, norm_port, norm_source, comment.strip(), 1 if is_enabled else 0, now, now))
    rule_id = cursor.lastrowid
    conn.commit()
    conn.close()

    apply_firewall()
    return rule_id

def update_rule(rule_id: int, action: str, protocol: str, port: str, source: str, comment: str, is_enabled: bool) -> bool:
    action = action.upper().strip()
    if action not in ("ALLOW", "DENY"):
        raise ValueError("Rule action must be ALLOW or DENY.")

    protocol = protocol.upper().strip()
    if protocol not in ("TCP", "UDP", "BOTH"):
        raise ValueError("Rule protocol must be TCP, UDP, or BOTH.")

    norm_port = normalize_port(port)
    norm_source = normalize_source(source)
    now = time.time()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE firewall_rules
        SET action = ?, protocol = ?, port = ?, source = ?, comment = ?, is_enabled = ?, updated_at = ?
        WHERE id = ?
    """, (action, protocol, norm_port, norm_source, comment.strip(), 1 if is_enabled else 0, now, rule_id))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()

    if updated:
        apply_firewall()
    return updated

def delete_rule(rule_id: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()

    if deleted:
        apply_firewall()
    return deleted

def toggle_rule(rule_id: int, is_enabled: bool) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE firewall_rules SET is_enabled = ?, updated_at = ? WHERE id = ?", (1 if is_enabled else 0, time.time(), rule_id))
    toggled = cursor.rowcount > 0
    conn.commit()
    conn.close()

    if toggled:
        apply_firewall()
    return toggled
