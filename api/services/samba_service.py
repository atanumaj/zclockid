"""
ZclockID Enterprise Management Appliance - Samba Active Directory Service
Manages direct LDB modifications, user provisioning, AD password policy enforcement, and DRS replication hooks.
"""

import subprocess
import re
import os
from typing import Optional, Dict, Any, List, Tuple
from fastapi import HTTPException
from api.core.config import SAMBA_LDB_PATH, DEFAULT_REALM
from api.core.security import get_ad_creds, validate_ad_password_complexity
from api.core.license import get_license_status
from api.services.system_service import run_cmd, log_audit, get_primary_realm

def update_user_upn(username: str, new_upn: str) -> str:
    code, stdout, stderr = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(sAMAccountName={username})", "dn"])
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
    proc = subprocess.run(["ldbmodify", "-H", str(SAMBA_LDB_PATH)], input=ldif, text=True, capture_output=True)
    if proc.returncode != 0:
        raise Exception(f"Failed to update userPrincipalName: {proc.stderr}")
    return dn

def parse_bw_info(info_str: Optional[str]) -> Optional[Dict[str, Any]]:
    """Parses ZCLOCKID_BW tag embedded in Active Directory user/group 'info' attribute."""
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

def format_bw_rate_str(d_val: Optional[float], u_val: Optional[float]) -> Optional[str]:
    """Formats download/upload speeds into human-readable rate strings, treating 0 as Unlimited."""
    if d_val is None or u_val is None:
        return None
    try:
        d = float(d_val)
        u = float(u_val)
    except (ValueError, TypeError):
        return None
    if d <= 0 and u <= 0:
        return "Unlimited"
    if d <= 0:
        return f"Unlimited / {u:g}M"
    if u <= 0:
        return f"{d:g}M / Unlimited"
    return f"{d:g}M/{u:g}M"

def provision_user_in_ad(
    username: str,
    password: str,
    given_name: str,
    surname: str,
    email: str,
    mobile: str,
    department: str,
    default_domain: Optional[str] = None,
    default_group: Optional[str] = None,
    default_bandwidth_profile_id: int = 0,
    is_self_registered: bool = True
) -> bool:
    # License capacity check
    code_cnt, stdout_cnt, _ = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        "(&(objectClass=user)(!(objectClass=computer)))", "sAMAccountName"
    ], timeout=5)
    current_count = 0
    if code_cnt == 0:
        for line in stdout_cnt.splitlines():
            line_str = line.strip()
            if line_str.startswith("sAMAccountName:") and not line_str.endswith("$"):
                current_count += 1

    lic_stat = get_license_status(current_count)
    if not lic_stat.get("can_create_user", True):
        max_u = lic_stat.get("max_users", 200)
        raise HTTPException(
            status_code=403,
            detail=f"User subscription limit reached ({current_count}/{max_u} users). An active ZclockID Enterprise license (zclockid.lic) is required to manage additional users. Please upload your license file under Security & Management > License."
        )

    admin_user, admin_pass = get_ad_creds()
    cmd = [
        "samba-tool", "user", "create", username, password,
        "--use-username-as-cn",
        f"-U{admin_user}", f"--password={admin_pass}"
    ]
    if given_name: cmd.extend(["--given-name", given_name])
    if surname: cmd.extend(["--surname", surname])
    if email: cmd.extend(["--mail-address", email])
    if mobile: cmd.extend(["--telephone-number", mobile])
    if department: cmd.extend(["--department", department])
    if is_self_registered:
        cmd.extend(["--description", "Self-Registered via ZclockID Portal"])

    code, stdout, stderr = run_cmd(cmd, timeout=25)
    if code != 0:
        err_out = (stderr or stdout or "").strip()
        if "check_password_restrictions" in err_out:
            err_out = "The password does not meet Active Directory complexity requirements (minimum 8 characters, containing uppercase, lowercase, numbers, and special symbols)."
        raise HTTPException(status_code=400, detail=f"Failed to create user in Active Directory: {err_out}")

    run_cmd(["samba-tool", "user", "setexpiry", username, "--noexpiry", f"-U{admin_user}", f"--password={admin_pass}"], timeout=10)

    # Active Directory Schema Attribute Synchronization via sam.ldb
    try:
        c_d, o_d, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(sAMAccountName={username})", "dn"])
        if c_d == 0 and "dn: " in o_d:
            u_dn = [l[4:].strip() for l in o_d.splitlines() if l.startswith("dn: ")][0]
            mod_lines = [f"dn: {u_dn}", "changetype: modify"]
            if department and department.strip():
                mod_lines.extend(["replace: department", f"department: {department.strip()}", "-"])
            if is_self_registered:
                mod_lines.extend([
                    "replace: employeeType", "employeeType: Self-Registered", "-",
                    "replace: comment", "comment: ZCLOCKID_SELF_REGISTERED", "-",
                    "replace: description", "description: Self-Registered via ZclockID Portal", "-"
                ])
            ldif_payload = "\n".join(mod_lines) + "\n"
            subprocess.run(["ldbmodify", "-H", str(SAMBA_LDB_PATH)], input=ldif_payload, text=True, capture_output=True)
    except Exception as e:
        print(f"Failed to set custom AD attributes on {username}: {e}")

    # Set Alternate UPN if specified
    if default_domain and default_domain.strip():
        chosen_dom = default_domain.strip().lower()
        upn_val = f"{username}@{chosen_dom}"
        try:
            update_user_upn(username, upn_val)
        except Exception as e:
            print(f"Failed to set UPN {upn_val} for {username}: {e}")

    # Add to default security group
    if default_group and default_group.strip() and default_group.strip().lower() != "domain users":
        grp_cmd = ["samba-tool", "group", "addmembers", default_group.strip(), username, f"-U{admin_user}", f"--password={admin_pass}"]
        run_cmd(grp_cmd, timeout=15)

    return True

