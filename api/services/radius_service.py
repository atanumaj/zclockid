"""
ZclockID Enterprise Management Appliance - FreeRADIUS 802.1X & QoS Policy Service
Generates dynamic /etc/freeradius/3.0/mods-config/files/authorize rules combining
MAB devices, AD user/group DRS-replicated bandwidth tiers, and fallback captive portal objects.
"""

import re
import datetime
import logging
from typing import Dict, Any, List, Optional
from api.core.config import (
    RADIUS_AUTHORIZE_FILE,
    RADIUS_USERS_FILE,
    SAMBA_LDB_PATH
)
from api.db.init_db import get_db_connection
from api.services.system_service import run_cmd
from api.services.samba_service import parse_bw_info, format_bw_rate_str

logger = logging.getLogger("zclockid.radius")

def get_self_registration_settings_dict() -> Dict[str, Any]:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM self_registration_settings WHERE id = 1")
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
    except Exception:
        pass
    return {"default_bandwidth_profile_id": 0}

def sync_freeradius_policies() -> str:
    """Generates and writes FreeRADIUS authorize file with Bandwidth Rate Limiting, MAB devices, and custom attributes."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM radius_mab_devices WHERE is_active = 1 ORDER BY id ASC")
        mab_rows = [dict(r) for r in cursor.fetchall()]

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
    except Exception as e:
        logger.warning(f"Failed to query database for FreeRADIUS policies: {e}")
        mab_rows, user_bw_rows, bw_rows, custom_rows = [], [], [], []

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

    # 2. Individual User Bandwidth Profiles (Top Priority - DRS Multi-Master Replicated)
    ad_user_overrides = {}
    code_ad, out_ad, _ = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        "(&(sAMAccountType=805306368)(info=ZCLOCKID_BW:*))", "sAMAccountName", "info"
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

    merged_user_bw = {}
    for ubw in user_bw_rows:
        merged_user_bw[ubw['username']] = ubw
    for u_name, u_data in ad_user_overrides.items():
        merged_user_bw[u_name] = u_data

    if merged_user_bw:
        lines.append("# --- Individual User Bandwidth Profiles (Top Priority - DRS Multi-Master Replicated) ---")
        for u_name, ubw in sorted(merged_user_bw.items()):
            down_mbps = float(ubw.get('download_mbps', 0))
            up_mbps = float(ubw.get('upload_mbps', 0))
            down_bps = int(down_mbps * 1000000)
            up_bps = int(up_mbps * 1000000)
            rate_label = format_bw_rate_str(down_mbps, up_mbps) or "Default"
            sess_sec = int(ubw.get('session_timeout_mins', 0) * 60)
            idle_sec = int(ubw.get('idle_timeout_mins', 0) * 60)
            quota_bytes = int(ubw.get('daily_quota_mb', 0) * 1024 * 1024)

            lines.append(f'# User Override: {u_name} -> Tier: {ubw.get("name", "Custom")} ({rate_label}) [DRS Replicated]')
            lines.append(f'"{u_name}"')
            if down_bps > 0:
                lines.append(f'\tWISPr-Bandwidth-Max-Down = {down_bps},')
            if up_bps > 0:
                lines.append(f'\tWISPr-Bandwidth-Max-Up = {up_bps},')
            if down_bps > 0 or up_bps > 0:
                lines.append(f'\tMikrotik-Rate-Limit = "{up_mbps:g}M/{down_mbps:g}M",')
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
    ad_group_overrides = {}
    code_g, out_g, _ = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
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

    merged_group_bw = dict(ad_group_overrides)

    if merged_group_bw:
        lines.append("# --- Active Directory Group Bandwidth Profiles (DRS Multi-Master Replicated) ---")
        def group_sort_key(item):
            d = float(item[1].get('download_mbps', 0))
            u = float(item[1].get('upload_mbps', 0))
            effective_d = float('inf') if d <= 0 else d
            effective_u = float('inf') if u <= 0 else u
            return (effective_d, effective_u)

        sorted_groups = sorted(merged_group_bw.items(), key=group_sort_key, reverse=True)
        for group_name, bw in sorted_groups:
            down_mbps = float(bw.get('download_mbps', 0))
            up_mbps = float(bw.get('upload_mbps', 0))
            down_bps = int(down_mbps * 1000000)
            up_bps = int(up_mbps * 1000000)
            rate_label = format_bw_rate_str(down_mbps, up_mbps) or "Default"
            sess_sec = int(bw.get('session_timeout_mins', 0) * 60)
            idle_sec = int(bw.get('idle_timeout_mins', 0) * 60)
            quota_bytes = int(bw.get('daily_quota_mb', 0) * 1024 * 1024)

            lines.append(f'# Group Profile: {bw.get("name", "Custom")} (AD Group: {group_name}) ({rate_label}) [DRS Replicated]')
            lines.append(f'DEFAULT Group == "{group_name}"')
            if down_bps > 0:
                lines.append(f'\tWISPr-Bandwidth-Max-Down = {down_bps},')
            if up_bps > 0:
                lines.append(f'\tWISPr-Bandwidth-Max-Up = {up_bps},')
            if down_bps > 0 or up_bps > 0:
                lines.append(f'\tMikrotik-Rate-Limit = "{up_mbps:g}M/{down_mbps:g}M",')
            lines.append('\tAcct-Interim-Interval = 300,')
            if sess_sec > 0:
                lines.append(f'\tSession-Timeout = {sess_sec},')
            if idle_sec > 0:
                lines.append(f'\tIdle-Timeout = {idle_sec},')
            if quota_bytes > 0:
                lines.append(f'\tChilliSpot-Max-Total-Octets = {quota_bytes},')
                lines.append(f'\tMikrotik-Total-Limit = {quota_bytes},')
            lines.append('\tFall-Through = No\n')

    # 4. Default Captive Portal Tier (Fallback)
    reg_settings = get_self_registration_settings_dict()
    def_bw_id = reg_settings.get("default_bandwidth_profile_id") or 0
    default_bw = next((b for b in bw_rows if b.get('id') == def_bw_id), None)
    if default_bw:
        down_mbps = float(default_bw.get('download_mbps', 0))
        up_mbps = float(default_bw.get('upload_mbps', 0))
        down_bps = int(down_mbps * 1000000)
        up_bps = int(up_mbps * 1000000)
        rate_label = format_bw_rate_str(down_mbps, up_mbps) or "Default"
        sess_sec = int(default_bw['session_timeout_mins'] * 60) if default_bw.get('session_timeout_mins') else 0
        idle_sec = int(default_bw['idle_timeout_mins'] * 60) if default_bw.get('idle_timeout_mins') else 0
        quota_bytes = int(default_bw['daily_quota_mb'] * 1024 * 1024) if default_bw.get('daily_quota_mb') else 0

        lines.append(f'# Default Captive Portal Tier: {default_bw["name"]} ({rate_label})')
        lines.append('DEFAULT')
        if down_bps > 0:
            lines.append(f'\tWISPr-Bandwidth-Max-Down = {down_bps},')
        if up_bps > 0:
            lines.append(f'\tWISPr-Bandwidth-Max-Up = {up_bps},')
        if down_bps > 0 or up_bps > 0:
            lines.append(f'\tMikrotik-Rate-Limit = "{up_mbps:g}M/{down_mbps:g}M",')
        lines.append('\tAcct-Interim-Interval = 300,')
        if sess_sec > 0:
            lines.append(f'\tSession-Timeout = {sess_sec},')
        if idle_sec > 0:
            lines.append(f'\tIdle-Timeout = {idle_sec},')
        if quota_bytes > 0:
            lines.append(f'\tChilliSpot-Max-Total-Octets = {quota_bytes},')
            lines.append(f'\tMikrotik-Total-Limit = {quota_bytes},')
        lines.append('\tFall-Through = Yes\n')
    else:
        lines.append('# Default Captive Portal Tier: None (Standard Unthrottled Fallback)')
        lines.append('DEFAULT')
        lines.append('\tAcct-Interim-Interval = 300,')
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

    for target_path in [RADIUS_AUTHORIZE_FILE, RADIUS_USERS_FILE]:
        if target_path.parent.exists():
            try:
                target_path.write_text(content)
            except Exception as e:
                logger.warning(f"Could not write {target_path}: {e}")

    run_cmd(["systemctl", "reload", "freeradius"])
    return content
