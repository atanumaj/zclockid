"""
ZclockID Enterprise Management Appliance - Identity & Directory Objects Router
Provides comprehensive REST management for Active Directory Users, Groups, and Computer accounts.
Implements Zero-Shadow Directory State: reads directly from Samba sam.ldb and respects RSAT modifications.
"""

from fastapi import APIRouter, HTTPException, status
import subprocess
import time
import re
import os
import sqlite3
import logging
from typing import Dict, Any, List, Optional
from api.core.config import SAMBA_LDB_PATH, DB_PATH
from api.core.security import get_ad_creds, validate_ad_password_complexity
from api.services.system_service import run_cmd, log_audit, get_primary_realm
from api.services.samba_service import parse_bw_info, format_bw_rate_str, update_user_upn
from api.services.radius_service import sync_freeradius_policies
from api.schemas.user_schema import (
    UserCreateRequest,
    UserUpdateRequest,
    UserPasswordReset,
    UserUpnUpdateRequest,
    GroupCreateRequest,
    GroupUpdateRequest
)

logger = logging.getLogger("zclockid.users")
router = APIRouter(prefix="/api/v1", tags=["Active Directory Identity Objects"])

PROTECTED_BUILTIN_GROUPS = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "domain users", "domain guests", "domain computers", "domain controllers",
    "group policy creator owners", "cert publishers", "ras and ias servers",
    "allowed rodc password replication group", "denied rodc password replication group",
    "read-only domain controllers", "enterprise read-only domain controllers",
    "dnsupdateproxy", "dnsadmins"
}

@router.get("/users")
def list_domain_users():
    """Lists all Active Directory user accounts with department, UPN, status, and bandwidth policies."""
    primary_realm = get_primary_realm().lower()
    code, stdout, stderr = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        "(objectClass=user)",
        "sAMAccountName", "userPrincipalName", "givenName", "sn", "displayName", "mail", "telephoneNumber", "department", "info", "userAccountControl", "memberOf", "employeeType", "comment", "description"
    ], timeout=10)

    user_bw_map = {}
    profiles_by_name = {}
    all_profiles = []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.username, u.profile_id, p.name as profile_name, p.download_mbps, p.upload_mbps
            FROM radius_user_bandwidth u
            JOIN radius_bandwidth_profiles p ON u.profile_id = p.id
            WHERE p.is_active = 1
        """)
        for row in cursor.fetchall():
            user_bw_map[row["username"]] = dict(row)

        cursor.execute("SELECT * FROM radius_bandwidth_profiles WHERE is_active = 1")
        all_profiles = [dict(r) for r in cursor.fetchall()]
        profiles_by_name = {r["name"].lower(): r["id"] for r in all_profiles}
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to read radius_user_bandwidth: {e}")

    group_bw_map = {}
    code_grp, out_grp, _ = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        "(&(objectClass=group)(info=ZCLOCKID_BW:*))", "sAMAccountName", "info"
    ], timeout=5)
    if code_grp == 0:
        c_g = {}
        for line in out_grp.splitlines():
            line = line.strip()
            if not line:
                if c_g.get("name") and c_g.get("info"):
                    bw = parse_bw_info(c_g["info"])
                    if bw:
                        group_bw_map[c_g["name"].lower()] = {
                            "group_name": c_g["name"],
                            "profile_name": bw["name"],
                            "download_mbps": bw["download_mbps"],
                            "upload_mbps": bw["upload_mbps"],
                            "rate_str": format_bw_rate_str(bw["download_mbps"], bw["upload_mbps"])
                        }
                c_g = {}
                continue
            if line.startswith("sAMAccountName:"):
                c_g["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("info:"):
                c_g["info"] = line.split(":", 1)[1].strip()
        if c_g.get("name") and c_g.get("info"):
            bw = parse_bw_info(c_g["info"])
            if bw:
                group_bw_map[c_g["name"].lower()] = {
                    "group_name": c_g["name"],
                    "profile_name": bw["name"],
                    "download_mbps": bw["download_mbps"],
                    "upload_mbps": bw["upload_mbps"],
                    "rate_str": format_bw_rate_str(bw["download_mbps"], bw["upload_mbps"])
                }

    for prof in all_profiles:
        grp = prof.get("ad_group") or (prof.get("target_name") if prof.get("target_type") == "GROUP" else None)
        if grp and grp.lower() not in group_bw_map:
            group_bw_map[grp.lower()] = {
                "group_name": grp,
                "profile_name": prof["name"],
                "download_mbps": prof["download_mbps"],
                "upload_mbps": prof["upload_mbps"],
                "rate_str": format_bw_rate_str(prof["download_mbps"], prof["upload_mbps"])
            }

    users = []
    if code == 0:
        current_user = {"groups": []}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current_user.get("username"):
                    u = current_user["username"]
                    if not u.endswith("$"):
                        is_built_in = u.lower() in ["administrator", "guest", "krbtgt", "dns-inet-zclockid"] or u.lower().startswith("dns-")
                        is_system_hidden = u.lower() in ["guest", "krbtgt", "dns-inet-zclockid"] or u.lower().startswith("dns-")
                        uac = current_user.get("uac", 512)
                        is_disabled = (uac & 2) != 0 or u in ["Guest", "krbtgt"]
                        upn = current_user.get("user_principal_name") or f"{u}@{primary_realm}"
                        bw_entry = user_bw_map.get(u)
                        bw_parsed = parse_bw_info(current_user.get("info"))

                        p_name = bw_parsed["name"] if bw_parsed else (bw_entry["profile_name"] if bw_entry else None)
                        p_id = bw_entry["profile_id"] if bw_entry else (profiles_by_name.get(p_name.lower()) if p_name else None)
                        d_val = bw_parsed["download_mbps"] if bw_parsed else (bw_entry["download_mbps"] if bw_entry else None)
                        u_val = bw_parsed["upload_mbps"] if bw_parsed else (bw_entry["upload_mbps"] if bw_entry else None)
                        bw_rate_str = format_bw_rate_str(d_val, u_val)

                        g_name = current_user.get("given_name") or ""
                        s_name = current_user.get("surname") or ""
                        full_name = current_user.get("display_name") or f"{g_name} {s_name}".strip() or u
                        dept_val = "Built-in" if is_built_in else (current_user.get("department") or "-")

                        best_grp_bw = None
                        for grp_item in current_user.get("groups", []):
                            g_pol = group_bw_map.get(grp_item.lower())
                            if g_pol:
                                if best_grp_bw is None:
                                    best_grp_bw = g_pol
                                else:
                                    speed_new = float('inf') if (g_pol["download_mbps"] == 0 or g_pol["download_mbps"] is None) else g_pol["download_mbps"]
                                    speed_cur = float('inf') if (best_grp_bw["download_mbps"] == 0 or best_grp_bw["download_mbps"] is None) else best_grp_bw["download_mbps"]
                                    if speed_new > speed_cur:
                                        best_grp_bw = g_pol

                        emp_type = (current_user.get("employee_type") or "").lower()
                        u_comment = current_user.get("comment") or ""
                        u_desc = (current_user.get("description") or "").lower()
                        is_self_reg = (emp_type == "self-registered") or ("ZCLOCKID_SELF_REGISTERED" in u_comment) or ("self-registered" in u_desc)

                        users.append({
                            "username": u,
                            "name": full_name,
                            "given_name": g_name,
                            "surname": s_name,
                            "user_principal_name": upn,
                            "email": current_user.get("email") or "",
                            "mobile": current_user.get("mobile") or "",
                            "department": dept_val,
                            "status": "disabled" if is_disabled else "active",
                            "is_disabled": is_disabled,
                            "is_built_in": is_built_in,
                            "is_system_hidden": is_system_hidden,
                            "is_self_registered": is_self_reg,
                            "groups": current_user.get("groups", []),
                            "bandwidth_profile_id": p_id,
                            "bandwidth_profile_name": p_name,
                            "bandwidth_rate": bw_rate_str,
                            "group_bandwidth_profile_name": best_grp_bw["profile_name"] if best_grp_bw else None,
                            "group_bandwidth_rate": best_grp_bw["rate_str"] if best_grp_bw else None,
                            "group_bandwidth_group": best_grp_bw["group_name"] if best_grp_bw else None
                        })
                current_user = {"groups": []}
                continue

            if line.startswith("sAMAccountName:"):
                current_user["username"] = line.split(":", 1)[1].strip()
            elif line.startswith("userPrincipalName:"):
                current_user["user_principal_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("givenName:"):
                current_user["given_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("sn:"):
                current_user["surname"] = line.split(":", 1)[1].strip()
            elif line.startswith("displayName:"):
                current_user["display_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("mail:"):
                current_user["email"] = line.split(":", 1)[1].strip()
            elif line.startswith("telephoneNumber:"):
                current_user["mobile"] = line.split(":", 1)[1].strip()
            elif line.startswith("department:"):
                current_user["department"] = line.split(":", 1)[1].strip()
            elif line.startswith("info:"):
                current_user["info"] = line.split(":", 1)[1].strip()
            elif line.startswith("employeeType:"):
                current_user["employee_type"] = line.split(":", 1)[1].strip()
            elif line.startswith("comment:"):
                current_user["comment"] = line.split(":", 1)[1].strip()
            elif line.startswith("description:"):
                current_user["description"] = line.split(":", 1)[1].strip()
            elif line.startswith("memberOf:"):
                dn_val = line.split(":", 1)[1].strip()
                for part in dn_val.split(","):
                    if part.strip().startswith("CN="):
                        grp_name = part.strip()[3:]
                        if grp_name not in current_user.setdefault("groups", []):
                            current_user["groups"].append(grp_name)
                        break
            elif line.startswith("userAccountControl:"):
                try:
                    current_user["uac"] = int(line.split(":", 1)[1].strip())
                except:
                    current_user["uac"] = 512

    return {"count": len(users), "users": users}

@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_domain_user(req: UserCreateRequest):
    """Creates a new Active Directory domain user with complexity validation and schema attributes."""
    is_valid, err_msg = validate_ad_password_complexity(req.password, req.username, f"{req.given_name or ''} {req.surname or ''}")
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    admin_user, admin_pass = get_ad_creds()
    cmd = [
        "samba-tool", "user", "create", req.username, req.password,
        "--use-username-as-cn",
        f"-U{admin_user}", f"--password={admin_pass}"
    ]
    if req.given_name: cmd.extend(["--given-name", req.given_name])
    if req.surname: cmd.extend(["--surname", req.surname])
    if req.email: cmd.extend(["--mail-address", req.email])
    if req.mobile: cmd.extend(["--telephone-number", req.mobile])
    if req.department: cmd.extend(["--department", req.department])

    code, stdout, stderr = run_cmd(cmd, timeout=20)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to create user: {stderr or stdout}")

    target_groups = set(req.groups or [])
    if req.target_group and req.target_group != "Domain Users":
        target_groups.add(req.target_group)
    for grp in target_groups:
        if grp and grp.lower() != "domain users":
            run_cmd(["samba-tool", "group", "addmembers", grp, req.username, f"-U{admin_user}", f"--password={admin_pass}"])

    if target_groups:
        sync_freeradius_policies()

    if req.bandwidth_profile_id and req.bandwidth_profile_id > 0:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM radius_bandwidth_profiles WHERE id = ?", (req.bandwidth_profile_id,))
            p_row = cursor.fetchone()

            cursor.execute("""
                INSERT INTO radius_user_bandwidth (username, profile_id, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET profile_id = excluded.profile_id, updated_at = excluded.updated_at
            """, (req.username, req.bandwidth_profile_id, time.time()))
            conn.commit()
            conn.close()

            if p_row:
                p = dict(p_row)
                bw_tag = f"ZCLOCKID_BW:{p['name']};down={p['download_mbps']};up={p['upload_mbps']};sess={p.get('session_timeout_mins', 120)};idle={p.get('idle_timeout_mins', 30)};quota={p.get('daily_quota_mb', 0)}"
                c_d, o_d, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(sAMAccountName={req.username})", "dn"])
                if c_d == 0 and "dn: " in o_d:
                    for l in o_d.splitlines():
                        if l.startswith("dn: "):
                            u_dn = l[4:].strip()
                            ldif = f"dn: {u_dn}\nchangetype: modify\nreplace: info\ninfo: {bw_tag}\n-\n"
                            subprocess.run(["ldbmodify", "-H", str(SAMBA_LDB_PATH)], input=ldif, text=True, capture_output=True)
                            break
            sync_freeradius_policies()
        except Exception as e:
            logger.warning(f"Failed to assign user bandwidth on create: {e}")

    log_audit("USER_CREATED", "admin", req.username, "SUCCESS", {"group": req.target_group, "bandwidth_profile_id": req.bandwidth_profile_id})
    return {"status": "success", "username": req.username, "message": f"User {req.username} provisioned successfully."}

@router.put("/users/{username}")
def update_domain_user(username: str, req: UserUpdateRequest):
    """Updates user attributes, password, status, and bandwidth tier."""
    code, stdout, stderr = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(sAMAccountName={username})", "dn"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to query SAM LDB: {stderr}")
    dn = None
    for line in stdout.splitlines():
        if line.startswith("dn: "):
            dn = line[4:].strip()
            break
    if not dn:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found in Active Directory.")

    bw_info_tag = None
    if req.bandwidth_profile_id is not None:
        if req.bandwidth_profile_id > 0:
            try:
                conn_b = sqlite3.connect(DB_PATH)
                conn_b.row_factory = sqlite3.Row
                c_b = conn_b.cursor()
                c_b.execute("SELECT * FROM radius_bandwidth_profiles WHERE id = ?", (req.bandwidth_profile_id,))
                p_r = c_b.fetchone()
                conn_b.close()
                if p_r:
                    p = dict(p_r)
                    bw_info_tag = f"ZCLOCKID_BW:{p['name']};down={p['download_mbps']};up={p['upload_mbps']};sess={p.get('session_timeout_mins', 120)};idle={p.get('idle_timeout_mins', 30)};quota={p.get('daily_quota_mb', 0)}"
            except Exception as e:
                logger.warning(f"Failed to lookup profile details: {e}")
        else:
            bw_info_tag = ""

    ldif_lines = [f"dn: {dn}", "changetype: modify"]
    has_modifications = False

    attr_map = [
        ("givenName", req.given_name),
        ("sn", req.surname),
        ("mail", req.email),
        ("telephoneNumber", req.mobile),
        ("department", req.department),
        ("userPrincipalName", req.user_principal_name)
    ]
    if bw_info_tag is not None:
        attr_map.append(("info", bw_info_tag))

    for attr, val in attr_map:
        if val is not None:
            val_clean = str(val).strip()
            if val_clean:
                ldif_lines.extend([f"replace: {attr}", f"{attr}: {val_clean}", "-"])
            else:
                ldif_lines.extend([f"replace: {attr}", "-"])
            has_modifications = True

    if req.given_name is not None or req.surname is not None:
        g = req.given_name if req.given_name is not None else ""
        s = req.surname if req.surname is not None else ""
        disp = f"{g} {s}".strip() or username
        ldif_lines.extend(["replace: displayName", f"displayName: {disp}", "-"])
        has_modifications = True

    if has_modifications:
        ldif_content = "\n".join(ldif_lines) + "\n"
        proc = subprocess.run(["ldbmodify", "-H", str(SAMBA_LDB_PATH)], input=ldif_content, text=True, capture_output=True)
        if proc.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Failed to update user attributes: {proc.stderr}")

    admin_user, admin_pass = get_ad_creds()

    if req.new_password:
        p_code, p_out, p_err = run_cmd([
            "samba-tool", "user", "setpassword", username,
            f"--newpassword={req.new_password}",
            f"-U{admin_user}", f"--password={admin_pass}"
        ], timeout=15)
        if p_code != 0:
            raise HTTPException(status_code=400, detail=f"Failed to reset password: {p_err or p_out}")

    if req.is_disabled is not None:
        action = "disable" if req.is_disabled else "enable"
        s_code, s_out, s_err = run_cmd([
            "samba-tool", "user", action, username,
            f"-U{admin_user}", f"--password={admin_pass}"
        ], timeout=15)
        if s_code != 0:
            raise HTTPException(status_code=400, detail=f"Failed to {action} user: {s_err or s_out}")

    if req.bandwidth_profile_id is not None:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            now_ts = time.time()
            if req.bandwidth_profile_id > 0:
                cursor.execute("""
                    INSERT INTO radius_user_bandwidth (username, profile_id, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET profile_id = excluded.profile_id, updated_at = excluded.updated_at
                """, (username, req.bandwidth_profile_id, now_ts))
            else:
                cursor.execute("DELETE FROM radius_user_bandwidth WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            sync_freeradius_policies()
        except Exception as e:
            logger.warning(f"Failed to update user bandwidth profile: {e}")

    if req.groups is not None:
        c_m, o_m, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(sAMAccountName={username})", "memberOf"])
        current_user_groups = set()
        if c_m == 0:
            for l in o_m.splitlines():
                if l.startswith("memberOf:"):
                    dn_val = l.split(":", 1)[1].strip()
                    for part in dn_val.split(","):
                        if part.strip().startswith("CN="):
                            current_user_groups.add(part.strip()[3:])
                            break

        desired_groups = set(req.groups)
        to_add = desired_groups - current_user_groups
        to_remove = current_user_groups - desired_groups

        for grp in to_add:
            if grp and grp.lower() != "domain users":
                run_cmd(["samba-tool", "group", "addmembers", grp, username, f"-U{admin_user}", f"--password={admin_pass}"])

        for grp in to_remove:
            if grp and grp.lower() not in ["domain users", "domain guests"]:
                run_cmd(["samba-tool", "group", "removemembers", grp, username, f"-U{admin_user}", f"--password={admin_pass}"])

        sync_freeradius_policies()

    log_audit("USER_UPDATED", "admin", username, "SUCCESS", {
        "given_name": req.given_name,
        "surname": req.surname,
        "email": req.email,
        "department": req.department,
        "user_principal_name": req.user_principal_name,
        "bandwidth_profile_id": req.bandwidth_profile_id
    })

    return {"status": "success", "username": username, "message": f"User '{username}' updated successfully."}

@router.post("/users/{username}/password")
def set_user_password(username: str, req: UserPasswordReset):
    """Resets user password in Active Directory."""
    admin_user, admin_pass = get_ad_creds()
    cmd = ["samba-tool", "user", "setpassword", username, f"--newpassword={req.new_password}", f"-U{admin_user}", f"--password={admin_pass}"]
    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to set password: {stderr or stdout}")
    log_audit("USER_PASSWORD_RESET", "admin", username, "SUCCESS", {})
    return {"status": "success", "message": f"Password updated for {username}."}

@router.post("/users/{username}/disable")
def disable_user(username: str):
    """Disables an Active Directory user account."""
    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "user", "disable", username, f"-U{admin_user}", f"--password={admin_pass}"])
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to disable user: {stderr}")
    log_audit("USER_DISABLED", "admin", username, "SUCCESS", {})
    return {"status": "success", "message": f"User {username} disabled."}

@router.post("/users/{username}/enable")
def enable_user(username: str):
    """Enables an Active Directory user account."""
    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "user", "enable", username, f"-U{admin_user}", f"--password={admin_pass}"])
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to enable user: {stderr}")
    log_audit("USER_ENABLED", "admin", username, "SUCCESS", {})
    return {"status": "success", "message": f"User {username} enabled."}

@router.delete("/users/{username}")
def delete_domain_user(username: str):
    """Permanently deletes a user account from Active Directory."""
    if username.lower() in ["administrator", "guest", "krbtgt"]:
        raise HTTPException(status_code=400, detail=f"Cannot delete critical system account '{username}'.")

    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "user", "delete", username, f"-U{admin_user}", f"--password={admin_pass}"], timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to delete user: {stderr or stdout}")

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM radius_user_bandwidth WHERE username = ?", (username,))
        conn.commit()
        conn.close()
    except Exception:
        pass

    sync_freeradius_policies()
    log_audit("USER_DELETED", "admin", username, "SUCCESS", {})
    return {"status": "success", "message": f"User '{username}' deleted successfully."}

@router.get("/groups")
def list_domain_groups():
    """Lists all Active Directory security groups with member counts and assigned bandwidth profiles."""
    code, stdout, stderr = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        "(objectClass=group)",
        "sAMAccountName", "description", "info", "member"
    ], timeout=10)

    group_bw_map = {}
    profiles_by_name = {}
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM radius_bandwidth_profiles WHERE is_active = 1")
        for row in c.fetchall():
            r = dict(row)
            profiles_by_name[r["name"].lower()] = r
            if r.get("ad_group"):
                group_bw_map[r["ad_group"].lower()] = r
            if r.get("target_type") == "GROUP" and r.get("target_name"):
                group_bw_map[r["target_name"].lower()] = r
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to query bandwidth profiles for groups: {e}")

    groups = []
    if code == 0:
        current_grp = {}
        members = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current_grp.get("group_name"):
                    g_name = current_grp["group_name"]
                    grp_dn = current_grp.get("dn", "").lower()
                    is_builtin = ("cn=builtin" in grp_dn) or (g_name.lower() in PROTECTED_BUILTIN_GROUPS)
                    info_raw = current_grp.get("info")
                    bw_parsed = parse_bw_info(info_raw)

                    p_name = bw_parsed["name"] if bw_parsed else None
                    p_id = profiles_by_name.get(p_name.lower(), {}).get("id") if p_name else None
                    d_val = bw_parsed["download_mbps"] if bw_parsed else None
                    u_val = bw_parsed["upload_mbps"] if bw_parsed else None
                    rate_str = format_bw_rate_str(d_val, u_val)

                    groups.append({
                        "group_name": g_name,
                        "dn": current_grp.get("dn", ""),
                        "description": current_grp.get("description", ""),
                        "department": "Built-in" if is_builtin else "Custom Group",
                        "group_type": "Built-in" if is_builtin else "Custom Group",
                        "member_count": len(members),
                        "is_built_in": is_builtin,
                        "bandwidth_profile_id": p_id,
                        "bandwidth_profile_name": p_name,
                        "bandwidth_rate": rate_str
                    })
                current_grp = {}
                members = []
                continue

            if line.startswith("dn:"):
                current_grp["dn"] = line.split(":", 1)[1].strip()
            elif line.startswith("sAMAccountName:"):
                current_grp["group_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("description:"):
                current_grp["description"] = line.split(":", 1)[1].strip()
            elif line.startswith("info:"):
                current_grp["info"] = line.split(":", 1)[1].strip()
            elif line.startswith("member:"):
                members.append(line.split(":", 1)[1].strip())

    groups.sort(key=lambda x: (x["is_built_in"], x["group_name"].lower()))
    return {"count": len(groups), "groups": groups}

@router.post("/groups")
def create_domain_group(req: GroupCreateRequest):
    """Creates a new Active Directory Security Group and assigns optional Bandwidth policy."""
    admin_user, admin_pass = get_ad_creds()
    cmd = ["samba-tool", "group", "add", req.group_name, f"-U{admin_user}", f"--password={admin_pass}"]
    if req.description: cmd.extend(["--description", req.description])
    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to create group: {stderr or stdout}")

    if req.bandwidth_profile_id and req.bandwidth_profile_id > 0:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM radius_bandwidth_profiles WHERE id = ?", (req.bandwidth_profile_id,))
            p_row = c.fetchone()
            if p_row:
                p = dict(p_row)
                bw_tag = f"ZCLOCKID_BW:{p['name']};down={p['download_mbps']};up={p['upload_mbps']};sess={p.get('session_timeout_mins', 120)};idle={p.get('idle_timeout_mins', 30)};quota={p.get('daily_quota_mb', 0)}"
                c_d, o_d, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(&(objectClass=group)(sAMAccountName={req.group_name}))", "dn"])
                if c_d == 0 and "dn: " in o_d:
                    for l in o_d.splitlines():
                        if l.startswith("dn: "):
                            g_dn = l[4:].strip()
                            ldif = f"dn: {g_dn}\nchangetype: modify\nreplace: info\ninfo: {bw_tag}\n-\n"
                            subprocess.run(["ldbmodify", "-H", str(SAMBA_LDB_PATH)], input=ldif, text=True, capture_output=True)
                            break
                c.execute("UPDATE radius_bandwidth_profiles SET ad_group = ? WHERE id = ?", (req.group_name, req.bandwidth_profile_id))
                conn.commit()
            conn.close()
            sync_freeradius_policies()
        except Exception as e:
            logger.warning(f"Failed to assign bandwidth profile to group: {e}")

    log_audit("GROUP_CREATED", "admin", req.group_name, "SUCCESS", {"bandwidth_profile_id": req.bandwidth_profile_id})
    return {"status": "success", "group_name": req.group_name, "message": f"Security group '{req.group_name}' created successfully."}

@router.put("/groups/{group_name}")
def update_domain_group(group_name: str, req: GroupUpdateRequest):
    """Updates Active Directory Security Group description and assigned Bandwidth policy."""
    c_d, o_d, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(&(objectClass=group)(sAMAccountName={group_name}))", "dn"])
    if c_d != 0 or "dn: " not in o_d:
        raise HTTPException(status_code=404, detail=f"Group '{group_name}' not found in Active Directory.")

    g_dn = None
    for l in o_d.splitlines():
        if l.startswith("dn: "):
            g_dn = l[4:].strip()
            break

    if group_name.lower() in PROTECTED_BUILTIN_GROUPS or ("cn=builtin" in (g_dn or "").lower()):
        raise HTTPException(status_code=400, detail=f"Cannot modify protected built-in Active Directory group '{group_name}'.")

    ldif_lines = [f"dn: {g_dn}", "changetype: modify"]
    has_mod = False

    if req.description is not None:
        d_val = req.description.strip()
        if d_val:
            ldif_lines.extend(["replace: description", f"description: {d_val}", "-"])
        else:
            ldif_lines.extend(["replace: description", "-"])
        has_mod = True

    bw_info_tag = None
    if req.bandwidth_profile_id is not None:
        if req.bandwidth_profile_id > 0:
            try:
                conn = sqlite3.connect(DB_PATH)
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT * FROM radius_bandwidth_profiles WHERE id = ?", (req.bandwidth_profile_id,))
                p_row = c.fetchone()
                if p_row:
                    p = dict(p_row)
                    bw_info_tag = f"ZCLOCKID_BW:{p['name']};down={p['download_mbps']};up={p['upload_mbps']};sess={p.get('session_timeout_mins', 120)};idle={p.get('idle_timeout_mins', 30)};quota={p.get('daily_quota_mb', 0)}"
                    c.execute("UPDATE radius_bandwidth_profiles SET ad_group = ? WHERE id = ?", (group_name, req.bandwidth_profile_id))
                    conn.commit()
                conn.close()
            except Exception as e:
                logger.warning(f"Failed to lookup profile: {e}")
        else:
            bw_info_tag = ""
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("UPDATE radius_bandwidth_profiles SET ad_group = '' WHERE ad_group = ?", (group_name,))
                conn.commit()
                conn.close()
            except Exception:
                pass

    if bw_info_tag is not None:
        if bw_info_tag:
            ldif_lines.extend(["replace: info", f"info: {bw_info_tag}", "-"])
        else:
            ldif_lines.extend(["replace: info", "-"])
        has_mod = True

    if has_mod:
        ldif_content = "\n".join(ldif_lines) + "\n"
        proc = subprocess.run(["ldbmodify", "-H", str(SAMBA_LDB_PATH)], input=ldif_content, text=True, capture_output=True)
        if proc.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Failed to update group attributes: {proc.stderr}")

    sync_freeradius_policies()
    log_audit("GROUP_UPDATED", "admin", group_name, "SUCCESS", {"bandwidth_profile_id": req.bandwidth_profile_id})
    return {"status": "success", "group_name": group_name, "message": f"Group '{group_name}' updated successfully."}

@router.delete("/groups/{group_name}")
def delete_domain_group(group_name: str):
    """Deletes an Active Directory Security Group."""
    if group_name.lower() in PROTECTED_BUILTIN_GROUPS or ("cn=builtin" in group_name.lower()):
        raise HTTPException(status_code=400, detail=f"Cannot delete protected built-in Active Directory group '{group_name}'.")

    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "group", "delete", group_name, f"-U{admin_user}", f"--password={admin_pass}"], timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to delete group: {stderr or stdout}")

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE radius_bandwidth_profiles SET ad_group = '' WHERE ad_group = ?", (group_name,))
        conn.commit()
        conn.close()
    except Exception:
        pass

    sync_freeradius_policies()
    log_audit("GROUP_DELETED", "admin", group_name, "SUCCESS", {})
    return {"status": "success", "message": f"Security group '{group_name}' deleted successfully."}

@router.get("/computers")
def list_domain_computers():
    """Lists all Active Directory joined domain computers and servers."""
    code, stdout, stderr = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        "(objectClass=computer)",
        "sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion",
        "whenCreated", "userAccountControl", "dn"
    ], timeout=10)

    computers = []
    if code == 0:
        current_comp = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current_comp.get("name"):
                    uac = current_comp.get("uac", 4096)
                    is_dc = ("ou=domain controllers" in current_comp.get("dn", "").lower()) or ((uac & 8192) != 0)
                    is_disabled = (uac & 2) != 0

                    created_raw = current_comp.get("whenCreated", "")
                    created_str = created_raw[:8] if len(created_raw) >= 8 else "-"
                    if len(created_raw) >= 8:
                        try:
                            created_str = f"{created_raw[0:4]}-{created_raw[4:6]}-{created_raw[6:8]}"
                        except:
                            pass

                    computers.append({
                        "name": current_comp["name"],
                        "dns_hostname": current_comp.get("dNSHostName") or f"{current_comp['name'].lower()}.inet.net",
                        "operating_system": current_comp.get("operatingSystem") or "Windows / Linux Client",
                        "os_version": current_comp.get("operatingSystemVersion") or "-",
                        "is_dc": is_dc,
                        "role": "Domain Controller" if is_dc else "Domain Workstation",
                        "status": "disabled" if is_disabled else "active",
                        "is_disabled": is_disabled,
                        "created_at": created_str,
                        "dn": current_comp.get("dn", "")
                    })
                current_comp = {}
                continue

            if line.startswith("dn:"):
                current_comp["dn"] = line.split(":", 1)[1].strip()
            elif line.startswith("sAMAccountName:"):
                val = line.split(":", 1)[1].strip()
                if val.endswith("$"):
                    val = val[:-1]
                current_comp["name"] = val
            elif line.startswith("dNSHostName:"):
                current_comp["dNSHostName"] = line.split(":", 1)[1].strip()
            elif line.startswith("operatingSystem:"):
                current_comp["operatingSystem"] = line.split(":", 1)[1].strip()
            elif line.startswith("operatingSystemVersion:"):
                current_comp["operatingSystemVersion"] = line.split(":", 1)[1].strip()
            elif line.startswith("whenCreated:"):
                current_comp["whenCreated"] = line.split(":", 1)[1].strip()
            elif line.startswith("userAccountControl:"):
                try:
                    current_comp["uac"] = int(line.split(":", 1)[1].strip())
                except:
                    current_comp["uac"] = 4096

    return {"count": len(computers), "computers": computers}

@router.delete("/computers/{computer_name}")
def delete_domain_computer(computer_name: str):
    """Deletes a computer account from Active Directory."""
    c_d, o_d, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(&(objectClass=computer)(sAMAccountName={computer_name}$))", "dn"])
    if c_d != 0 or "dn: " not in o_d:
        raise HTTPException(status_code=404, detail=f"Computer account '{computer_name}' not found.")

    if "ou=domain controllers" in o_d.lower() or computer_name.upper() in ["INET-ZCLOCKID", "ZCLOCKID"]:
        raise HTTPException(status_code=400, detail="Cannot delete Domain Controller computer accounts.")

    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "computer", "delete", computer_name, f"-U{admin_user}", f"--password={admin_pass}"], timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to delete computer: {stderr or stdout}")

    log_audit("COMPUTER_DELETED", "admin", computer_name, "SUCCESS", {})
    return {"status": "success", "message": f"Computer account '{computer_name}' deleted successfully."}

