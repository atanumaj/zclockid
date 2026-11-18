"""
ZclockID Enterprise Management Appliance - Identity & Directory Objects Router
Provides comprehensive REST management for Active Directory Users, Groups, and Computer accounts.
Implements Zero-Shadow Directory State: reads directly from Samba sam.ldb and respects RSAT modifications.
"""

from fastapi import APIRouter, HTTPException, status, Depends
import subprocess
import time
import re
import os
import sqlite3
import logging
from typing import Dict, Any, List, Optional
from api.core.config import SAMBA_LDB_PATH, DB_PATH
from api.core.security import get_ad_creds, validate_ad_password_complexity
from api.core.license import get_license_status
from api.services.system_service import run_cmd, log_audit, get_primary_realm
from api.services.samba_service import parse_bw_info, format_bw_rate_str, update_user_upn
from api.services.radius_service import sync_freeradius_policies
from api.services.password_expiry_service import (
    get_password_expiry_report,
    apply_bulk_expiry_policy,
    get_user_password_info
)
from api.services.samdb_service import (
    samdb_newuser,
    samdb_setpassword,
    samdb_setexpiry,
    samdb_enable_account,
    samdb_disable_account,
    samdb_deleteuser,
    samdb_newgroup,
    samdb_deletegroup,
    samdb_add_group_member,
    samdb_remove_group_member,
    run_samba_tool_authenticated,
    escape_ldap_filter_value,
    SamDBUnavailableError
)
from api.routers.auth import require_role
from api.schemas.user_schema import (
    UserCreateRequest,
    UserUpdateRequest,
    UserPasswordReset,
    UserUpnUpdateRequest,
    GroupCreateRequest,
    GroupUpdateRequest
)

logger = logging.getLogger("zclockid.users")
router = APIRouter(prefix="/api/v1", tags=["Active Directory Identity Objects"], dependencies=[Depends(require_role("readonly"))])

PROTECTED_BUILTIN_GROUPS = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "domain users", "domain guests", "domain computers", "domain controllers",
    "group policy creator owners", "cert publishers", "ras and ias servers",
    "allowed rodc password replication group", "denied rodc password replication group",
    "read-only domain controllers", "enterprise read-only domain controllers",
    "dnsupdateproxy", "dnsadmins"
}

PRIVILEGED_GROUP_NAMES = {"domain admins", "enterprise admins", "schema admins", "administrators"}

def is_privileged_ad_user(username: str) -> bool:
    """
    Returns True if user is a privileged account:
    Administrator, krbtgt, Guest, or member of Domain Admins, Enterprise Admins,
    Schema Admins, or Administrators.
    """
    clean_name = (username or "").lower().strip()
    if clean_name in ("administrator", "krbtgt", "guest"):
        return True

    # Check MockSamDB state in mock test environments
    try:
        from api.services.samdb_service import get_samdb, MockSamDB
        db = get_samdb()
        if isinstance(db, MockSamDB):
            for grp_name, gdata in db.groups.items():
                if grp_name.lower() in PRIVILEGED_GROUP_NAMES:
                    members = gdata.get("members", set())
                    if username in members or clean_name in {m.lower() for m in members}:
                        return True
    except Exception:
        pass

    # Check live Active Directory sam.ldb
    try:
        clean_u = escape_ldap_filter_value(username)
        code, stdout, _ = run_cmd([
            "ldbsearch", "-H", str(SAMBA_LDB_PATH),
            f"(&(objectClass=user)(sAMAccountName={clean_u}))",
            "memberOf", "adminCount"
        ], timeout=5)
        if code == 0:
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("adminCount:"):
                    val = line.split(":", 1)[1].strip()
                    if val == "1":
                        return True
                elif line.startswith("memberOf:"):
                    line_lower = line.lower()
                    for pg in PRIVILEGED_GROUP_NAMES:
                        if f"cn={pg}," in line_lower or line_lower.endswith(f"cn={pg}"):
                            return True

            # Nested group membership query
            realm = get_primary_realm()
            if realm:
                b_dn = ",".join([f"DC={p}" for p in realm.split(".") if p])
                nested_filter = (
                    f"(&(objectClass=user)(sAMAccountName={clean_u})"
                    f"(|(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,{b_dn})"
                    f"(memberOf:1.2.840.113556.1.4.1941:=CN=Enterprise Admins,CN=Users,{b_dn})"
                    f"(memberOf:1.2.840.113556.1.4.1941:=CN=Schema Admins,CN=Users,{b_dn})"
                    f"(memberOf:1.2.840.113556.1.4.1941:=CN=Administrators,CN=Builtin,{b_dn})))"
                )
                c_n, out_n, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), nested_filter, "dn"], timeout=5)
                if c_n == 0 and "dn: " in out_n:
                    return True
    except Exception as e:
        logger.warning("Error checking privileged account status for %s: %s", username, e)

    return False

@router.get("/users")
def list_domain_users():
    """Lists all Active Directory user accounts with department, UPN, status, and bandwidth policies."""
    primary_realm = get_primary_realm().lower()
    code, stdout, stderr = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        "(objectClass=user)",
        "sAMAccountName", "userPrincipalName", "givenName", "sn", "displayName", "mail", "telephoneNumber", "department", "info", "userAccountControl", "memberOf", "employeeType", "comment", "description", "pwdLastSet", "msDS-ResultantPSO"
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
                        is_built_in = u.lower() in ["administrator", "guest", "krbtgt", "dns-zclockid"] or u.lower().startswith("dns-")
                        is_system_hidden = u.lower() in ["guest", "krbtgt", "dns-zclockid"] or u.lower().startswith("dns-")
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

                        never_exp = bool(uac & 65536)
                        pso_val = current_user.get("resultant_pso")
                        pwd_ls = current_user.get("pwd_last_set")
                        if never_exp:
                            exp_status = "Never"
                        elif pwd_ls == 0:
                            exp_status = "Expired (Must change)"
                        else:
                            exp_status = "Active"

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
                            "password_never_expires": never_exp,
                            "msDS_ResultantPSO": pso_val,
                            "expires_on": exp_status,
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
            elif line.startswith("pwdLastSet:"):
                try:
                    current_user["pwd_last_set"] = int(line.split(":", 1)[1].strip())
                except:
                    current_user["pwd_last_set"] = 0
            elif line.startswith("msDS-ResultantPSO:"):
                val = line.split(":", 1)[1].strip()
                for part in val.split(","):
                    if part.strip().startswith("CN="):
                        current_user["resultant_pso"] = part.strip()[3:]
                        break
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
    # License capacity check (Free tier up to 200 users; license required above 200 users)
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

    is_valid, err_msg = validate_ad_password_complexity(req.password, req.username, f"{req.given_name or ''} {req.surname or ''}")
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    try:
        samdb_newuser(
            username=req.username,
            password=req.password,
            given_name=req.given_name,
            surname=req.surname,
            email=req.email,
            mobile=req.mobile,
            department=req.department
        )
    except HTTPException:
        raise
    except Exception as e:
        err_out = str(e)
        if "check_password_restrictions" in err_out or "Constraint violation" in err_out:
            err_out = "The password does not meet Active Directory complexity requirements (minimum 8 characters, containing uppercase, lowercase, numbers, and special symbols)."
        raise HTTPException(status_code=400, detail=f"Failed to create user: {err_out}")

    if req.password_never_expires:
        try:
            samdb_setexpiry(req.username, noexpiry=True)
        except Exception as e:
            print(f"Failed to set noexpiry on {req.username}: {e}")

    target_groups = set(req.groups or [])
    if req.target_group and req.target_group != "Domain Users":
        target_groups.add(req.target_group)
    for grp in target_groups:
        if grp and grp.lower() != "domain users":
            try:
                samdb_add_group_member(grp, req.username)
            except Exception as e:
                print(f"Failed to add {req.username} to group {grp}: {e}")

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
def update_domain_user(
    username: str,
    req: UserUpdateRequest,
    current_user: dict = Depends(require_role("operator", "fulladmin"))
):
    """Updates user attributes, password, status, and bandwidth tier."""
    user_role = (current_user.get("role") or "").lower() if current_user else "admin"
    if user_role != "fulladmin" and is_privileged_ad_user(username):
        if req.new_password:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Resetting password on privileged accounts requires the fulladmin role."
            )
        if req.is_disabled is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Enabling or disabling privileged accounts requires the fulladmin role."
            )
        if req.password_never_expires is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Modifying password expiry settings on privileged accounts requires the fulladmin role."
            )

    clean_u = escape_ldap_filter_value(username)
    code, stdout, stderr = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(sAMAccountName={clean_u})", "dn"])
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

    if req.new_password:
        try:
            samdb_setpassword(username, req.new_password)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to reset password: {e}")

    if req.is_disabled is not None:
        try:
            if req.is_disabled:
                samdb_disable_account(username)
            else:
                samdb_enable_account(username)
        except HTTPException:
            raise
        except Exception as e:
            action = "disable" if req.is_disabled else "enable"
            raise HTTPException(status_code=400, detail=f"Failed to {action} user: {e}")

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
        c_m, o_m, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(sAMAccountName={escape_ldap_filter_value(username)})", "memberOf"])
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
                try:
                    samdb_add_group_member(grp, username)
                except Exception as e:
                    print(f"Failed to add {username} to {grp}: {e}")

        for grp in to_remove:
            if grp and grp.lower() not in ["domain users", "domain guests"]:
                try:
                    samdb_remove_group_member(grp, username)
                except Exception as e:
                    print(f"Failed to remove {username} from {grp}: {e}")

        sync_freeradius_policies()

    if req.password_never_expires is not None:
        if req.password_never_expires:
            try:
                samdb_setexpiry(username, noexpiry=True)
            except Exception as e:
                print(f"Failed to set noexpiry on {username}: {e}")
        else:
            c_u, o_u, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(sAMAccountName={escape_ldap_filter_value(username)})", "userAccountControl"])
            if c_u == 0:
                for l in o_u.splitlines():
                    if l.strip().startswith("userAccountControl:"):
                        try:
                            cur_uac = int(l.split(":", 1)[1].strip())
                            if cur_uac & 65536:
                                new_uac = cur_uac & ~65536
                                ldif_uac = f"dn: {dn}\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: {new_uac}\n-\n"
                                subprocess.run(["ldbmodify", "-H", str(SAMBA_LDB_PATH)], input=ldif_uac, text=True, capture_output=True)
                        except Exception as e:
                            logger.warning(f"Failed to clear DONT_EXPIRE_PASSWORD for {username}: {e}")

    log_audit("USER_UPDATED", "admin", username, "SUCCESS", {
        "given_name": req.given_name,
        "surname": req.surname,
        "email": req.email,
        "department": req.department,
        "user_principal_name": req.user_principal_name,
        "bandwidth_profile_id": req.bandwidth_profile_id
    })

    return {"status": "success", "username": username, "message": f"User '{username}' updated successfully."}

@router.get("/users/expiry-policy/report")
def get_expiry_report():
    """Generates password expiry compliance report across Active Directory."""
    return get_password_expiry_report()

@router.post("/users/expiry-policy/apply")
def apply_expiry_policy(current_user: dict = Depends(require_role("fulladmin"))):
    """Bulk action to apply password expiry policy to all eligible users, excluding Administrator and service accounts."""
    admin_name = current_user.get("username", "admin")
    return apply_bulk_expiry_policy(admin_name)

@router.get("/users/{username}")
def get_domain_user_detail(username: str):
    """Retrieves full user detail including msDS-ResultantPSO and password expiry date."""
    clean_u = escape_ldap_filter_value(username)
    code, stdout, stderr = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        f"(sAMAccountName={clean_u})",
        "sAMAccountName", "userPrincipalName", "givenName", "sn", "displayName", "mail", "telephoneNumber",
        "department", "info", "userAccountControl", "memberOf", "employeeType", "comment", "description",
        "pwdLastSet", "msDS-ResultantPSO", "accountExpires"
    ], timeout=10)

    if code != 0 or "sAMAccountName: " not in stdout:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found in Active Directory.")

    info = get_user_password_info(username)
    user_data = {
        "username": username,
        "password_never_expires": info.get("never_expires", False),
        "msDS_ResultantPSO": info.get("resultant_pso"),
        "expires_on": info.get("expires_on"),
        "is_expired": info.get("is_expired", False),
        "days_remaining": info.get("days_remaining"),
        "groups": []
    }
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("userPrincipalName:"): user_data["user_principal_name"] = line.split(":", 1)[1].strip()
        elif line.startswith("givenName:"): user_data["given_name"] = line.split(":", 1)[1].strip()
        elif line.startswith("sn:"): user_data["surname"] = line.split(":", 1)[1].strip()
        elif line.startswith("displayName:"): user_data["display_name"] = line.split(":", 1)[1].strip()
        elif line.startswith("mail:"): user_data["email"] = line.split(":", 1)[1].strip()
        elif line.startswith("telephoneNumber:"): user_data["mobile"] = line.split(":", 1)[1].strip()
        elif line.startswith("department:"): user_data["department"] = line.split(":", 1)[1].strip()
        elif line.startswith("memberOf:"):
            dn_val = line.split(":", 1)[1].strip()
            for part in dn_val.split(","):
                if part.strip().startswith("CN="):
                    user_data["groups"].append(part.strip()[3:])
                    break
        elif line.startswith("userAccountControl:"):
            try:
                uac_val = int(line.split(":", 1)[1].strip())
                user_data["is_disabled"] = bool(uac_val & 2)
                user_data["status"] = "disabled" if (uac_val & 2) else "active"
            except Exception:
                pass

    return user_data

@router.post("/users/{username}/password")
def set_user_password(
    username: str,
    req: UserPasswordReset,
    current_user: dict = Depends(require_role("operator", "fulladmin"))
):
    """Resets user password in Active Directory."""
    if (current_user.get("role") or "").lower() != "fulladmin" and is_privileged_ad_user(username):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Modifying privileged Active Directory accounts requires the fulladmin role."
        )
    try:
        samdb_setpassword(username, req.new_password)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to set password: {e}")
    actor = current_user.get("username", "admin")
    log_audit("USER_PASSWORD_RESET", actor, username, "SUCCESS", {})
    return {"status": "success", "message": f"Password updated for {username}."}

@router.post("/users/{username}/disable")
def disable_user(
    username: str,
    current_user: dict = Depends(require_role("operator", "fulladmin"))
):
    """Disables an Active Directory user account."""
    if (current_user.get("role") or "").lower() != "fulladmin" and is_privileged_ad_user(username):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Modifying privileged Active Directory accounts requires the fulladmin role."
        )
    try:
        samdb_disable_account(username)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to disable user: {e}")
    actor = current_user.get("username", "admin")
    log_audit("USER_DISABLED", actor, username, "SUCCESS", {})
    return {"status": "success", "message": f"User {username} disabled."}

@router.post("/users/{username}/enable")
def enable_user(
    username: str,
    current_user: dict = Depends(require_role("operator", "fulladmin"))
):
    """Enables an Active Directory user account."""
    if (current_user.get("role") or "").lower() != "fulladmin" and is_privileged_ad_user(username):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Modifying privileged Active Directory accounts requires the fulladmin role."
        )
    try:
        samdb_enable_account(username)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to enable user: {e}")
    actor = current_user.get("username", "admin")
    log_audit("USER_ENABLED", actor, username, "SUCCESS", {})
    return {"status": "success", "message": f"User {username} enabled."}

@router.delete("/users/{username}")
def delete_domain_user(
    username: str,
    current_user: dict = Depends(require_role("operator", "fulladmin"))
):
    """Permanently deletes a user account from Active Directory."""
    if username.lower() in ["administrator", "guest", "krbtgt"]:
        raise HTTPException(status_code=400, detail=f"Cannot delete critical system account '{username}'.")
    if (current_user.get("role") or "").lower() != "fulladmin" and is_privileged_ad_user(username):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Modifying privileged Active Directory accounts requires the fulladmin role."
        )

    try:
        samdb_deleteuser(username)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to delete user: {e}")

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
                    bw_entry = group_bw_map.get(g_name.lower().strip())

                    p_name = bw_parsed["name"] if bw_parsed else (bw_entry["name"] if bw_entry else None)
                    p_id = bw_entry["id"] if bw_entry else (profiles_by_name.get(p_name.lower(), {}).get("id") if p_name else None)
                    d_val = bw_parsed["download_mbps"] if bw_parsed else (bw_entry["download_mbps"] if bw_entry else None)
                    u_val = bw_parsed["upload_mbps"] if bw_parsed else (bw_entry["upload_mbps"] if bw_entry else None)
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

        if current_grp.get("group_name"):
            g_name = current_grp["group_name"]
            grp_dn = current_grp.get("dn", "").lower()
            is_builtin = ("cn=builtin" in grp_dn) or (g_name.lower() in PROTECTED_BUILTIN_GROUPS)
            info_raw = current_grp.get("info")
            bw_parsed = parse_bw_info(info_raw)
            bw_entry = group_bw_map.get(g_name.lower().strip())

            p_name = bw_parsed["name"] if bw_parsed else (bw_entry["name"] if bw_entry else None)
            p_id = bw_entry["id"] if bw_entry else (profiles_by_name.get(p_name.lower(), {}).get("id") if p_name else None)
            d_val = bw_parsed["download_mbps"] if bw_parsed else (bw_entry["download_mbps"] if bw_entry else None)
            u_val = bw_parsed["upload_mbps"] if bw_parsed else (bw_entry["upload_mbps"] if bw_entry else None)
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

    groups.sort(key=lambda x: (x["is_built_in"], x["group_name"].lower()))
    return {"count": len(groups), "groups": groups}

@router.post("/groups")
def create_domain_group(req: GroupCreateRequest):
    """Creates a new Active Directory Security Group and assigns optional Bandwidth policy."""
    try:
        samdb_newgroup(group_name=req.group_name, description=req.description)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create group: {e}")

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
                clean_req_grp = escape_ldap_filter_value(req.group_name)
                c_d, o_d, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(&(objectClass=group)(sAMAccountName={clean_req_grp}))", "dn"])
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
    clean_grp = escape_ldap_filter_value(group_name)
    c_d, o_d, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(&(objectClass=group)(sAMAccountName={clean_grp}))", "dn"])
    if c_d != 0 or "dn: " not in o_d:
        raise HTTPException(status_code=404, detail=f"Group '{group_name}' not found in Active Directory.")

    g_dn = None
    for l in o_d.splitlines():
        if l.startswith("dn: "):
            g_dn = l[4:].strip()
            break

    # Built-in groups can have QoS bandwidth policies and descriptions assigned/updated, but cannot be deleted.

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
                    c.execute("UPDATE radius_bandwidth_profiles SET ad_group = '', target_name = '' WHERE (ad_group = ? OR target_name = ?) AND id != ?", (group_name, group_name, req.bandwidth_profile_id))
                    c.execute("UPDATE radius_bandwidth_profiles SET ad_group = ?, target_name = ?, target_type = 'GROUP' WHERE id = ?", (group_name, group_name, req.bandwidth_profile_id))
                    conn.commit()
                conn.close()
            except Exception as e:
                logger.warning(f"Failed to lookup profile: {e}")
        else:
            bw_info_tag = ""
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("UPDATE radius_bandwidth_profiles SET ad_group = '', target_name = '' WHERE ad_group = ? OR target_name = ?", (group_name, group_name))
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
            logger.warning(f"ldbmodify notice on group '{group_name}': {proc.stderr}")
            if "Constraint violation" in proc.stderr or "Insufficient access rights" in proc.stderr:
                pass
            elif req.bandwidth_profile_id is None and req.description is not None:
                raise HTTPException(status_code=400, detail=f"Failed to update group description: {proc.stderr}")

    sync_freeradius_policies()
    log_audit("GROUP_UPDATED", "admin", group_name, "SUCCESS", {"bandwidth_profile_id": req.bandwidth_profile_id})
    return {"status": "success", "group_name": group_name, "message": f"Group '{group_name}' updated successfully."}

@router.delete("/groups/{group_name}")
def delete_domain_group(group_name: str):
    """Deletes an Active Directory Security Group."""
    if group_name.lower() in PROTECTED_BUILTIN_GROUPS or ("cn=builtin" in group_name.lower()):
        raise HTTPException(status_code=400, detail=f"Cannot delete protected built-in Active Directory group '{group_name}'.")

    try:
        samdb_deletegroup(group_name)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to delete group: {e}")

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

                    realm_suffix = get_primary_realm().lower()
                    dns_hn = current_comp.get("dNSHostName") or (f"{current_comp['name'].lower()}.{realm_suffix}" if realm_suffix else current_comp['name'])
                    computers.append({
                        "name": current_comp["name"],
                        "dns_hostname": dns_hn,
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
    clean_comp = escape_ldap_filter_value(computer_name)
    c_d, o_d, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), f"(&(objectClass=computer)(sAMAccountName={clean_comp}$))", "dn"])
    if c_d != 0 or "dn: " not in o_d:
        raise HTTPException(status_code=404, detail=f"Computer account '{computer_name}' not found.")

    if "ou=domain controllers" in o_d.lower() or computer_name.upper() in ["ZCLOCKID-DC", "ZCLOCKID"]:
        raise HTTPException(status_code=400, detail="Cannot delete Domain Controller computer accounts.")

    code, stdout, stderr = run_samba_tool_authenticated(["computer", "delete", computer_name], timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to delete computer: {stderr or stdout}")

    log_audit("COMPUTER_DELETED", "admin", computer_name, "SUCCESS", {})
    return {"status": "success", "message": f"Computer account '{computer_name}' deleted successfully."}

