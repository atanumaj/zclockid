"""
ZclockID Role-Based Access Control (RBAC) Router
Provides Hybrid Directory Mapping (Active Directory + Local Break-Glass)
"""

import time
import sqlite3
import subprocess
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Header, status

from api.core.config import DB_PATH, SAMBA_LDB_PATH
from api.services.system_service import log_audit, run_cmd
from api.schemas.rbac_schema import (
    RbacMappingCreateRequest,
    RbacMappingUpdateRequest,
    RbacMappingResponse,
    UserPermissionsResponse,
    VALID_ROLES
)

router = APIRouter(prefix="/api/v1/rbac", tags=["Access Control & RBAC"])

ROLE_PERMISSIONS = {
    "fulladmin": [
        "*"
    ],
    "operator": [
        "users:read", "users:write",
        "groups:read", "groups:write",
        "registrations:read", "registrations:write",
        "radius:read", "radius:write",
        "dns:read", "dns:write",
        "system:read"
    ],
    "report": [
        "system:read",
        "reports:read",
        "telemetry:read",
        "sysvol:read",
        "radius:read",
        "logs:read",
        "users:read",
        "groups:read"
    ],
    "readonly": [
        "*:read"
    ]
}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_user_ad_groups(username: str) -> List[str]:
    """Retrieves Active Directory group memberships for a user via samba-tool."""
    code, stdout, _ = run_cmd(["samba-tool", "user", "getgroups", username], timeout=8)
    if code == 0 and stdout:
        return [g.strip() for g in stdout.splitlines() if g.strip()]
    return []

def resolve_user_role(username: str, is_local_admin: bool = False) -> tuple:
    """
    Resolves the effective role for a user.
    Precedence: Direct User Mapping -> Highest Group Mapping -> Default (readonly/fulladmin for local).
    """
    clean_user = username.strip().lower()

    conn = get_db()
    cursor = conn.cursor()

    # 1. Check direct user mapping
    cursor.execute("SELECT role FROM rbac_mappings WHERE principal_type = 'user' AND LOWER(principal_name) = ?", (clean_user,))
    row = cursor.fetchone()
    if row:
        conn.close()
        return row["role"], []

    # If user is local admin and no direct override exists, grant fulladmin (break-glass)
    if is_local_admin:
        conn.close()
        return "fulladmin", []

    # 2. Check group mappings for AD user
    ad_groups = get_user_ad_groups(clean_user)
    if ad_groups:
        cursor.execute("SELECT principal_name, role FROM rbac_mappings WHERE principal_type = 'group'")
        group_mappings = cursor.fetchall()
        conn.close()

        mapping_dict = {r["principal_name"].lower(): r["role"] for r in group_mappings}
        matched_roles = []
        for g in ad_groups:
            if g.lower() in mapping_dict:
                matched_roles.append(mapping_dict[g.lower()])

        # Prioritize roles: fulladmin > operator > report > readonly
        priority = ["fulladmin", "operator", "report", "readonly"]
        for p in priority:
            if p in matched_roles:
                return p, ad_groups

    conn.close()
    # Default fallback role for authenticated domain users without mapping
    return "readonly", ad_groups

def get_current_user_from_token(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization header missing.")
    token = authorization.replace("Bearer ", "").strip()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role, expires_at FROM sessions WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()

    if not row or row["expires_at"] < time.time():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session token.")

    return {
        "username": row["username"],
        "role": row["role"] or "readonly"
    }

# ----------------- Endpoints -----------------

@router.get("/roles")
def list_available_roles():
    """Returns all supported appliance roles, hierarchy, and permissions description."""
    return {
        "roles": [
            {
                "id": "fulladmin",
                "name": "Full Administrator",
                "badge_color": "emerald",
                "description": "Unrestricted read and write access across all domains, services, certificates, and system settings.",
                "permissions": ROLE_PERMISSIONS["fulladmin"]
            },
            {
                "id": "operator",
                "name": "User & Identity Operator",
                "badge_color": "indigo",
                "description": "Can manage Active Directory users, groups, bandwidth tiers, and approve self-registrations. System configurations and backups are locked.",
                "permissions": ROLE_PERMISSIONS["operator"]
            },
            {
                "id": "report",
                "name": "Auditor & Reporting",
                "badge_color": "cyan",
                "description": "Read-only access to telemetry, Sysvol sync health, active RADIUS sessions, and Syslog viewers. Mutation actions are forbidden.",
                "permissions": ROLE_PERMISSIONS["report"]
            },
            {
                "id": "readonly",
                "name": "Read-Only Inspector",
                "badge_color": "slate",
                "description": "Complete view-only inspection access. All modification buttons and endpoints are disabled.",
                "permissions": ROLE_PERMISSIONS["readonly"]
            }
        ]
    }

@router.get("/principals")
def list_ad_principals():
    """Lists Active Directory security groups and user accounts from sam.ldb for RBAC dropdowns."""
    groups = []
    users = []

    # 1. Query AD Security Groups
    code, stdout, _ = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        "(objectClass=group)", "sAMAccountName", "description"
    ], timeout=5)
    if code == 0 and stdout:
        cur_name = ""
        cur_desc = ""
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if cur_name:
                    groups.append({"name": cur_name, "description": cur_desc})
                    cur_name = ""
                    cur_desc = ""
            elif line.startswith("sAMAccountName:"):
                cur_name = line.split(":", 1)[1].strip()
            elif line.startswith("description:"):
                cur_desc = line.split(":", 1)[1].strip()
        if cur_name:
            groups.append({"name": cur_name, "description": cur_desc})

    # 2. Query AD User Accounts (excluding computer objects)
    code_u, stdout_u, _ = run_cmd([
        "ldbsearch", "-H", str(SAMBA_LDB_PATH),
        "(&(objectClass=user)(!(objectClass=computer)))", "sAMAccountName", "displayName"
    ], timeout=5)
    if code_u == 0 and stdout_u:
        cur_name = ""
        cur_disp = ""
        for line in stdout_u.splitlines():
            line = line.strip()
            if not line:
                if cur_name:
                    users.append({"name": cur_name, "display_name": cur_disp})
                    cur_name = ""
                    cur_disp = ""
            elif line.startswith("sAMAccountName:"):
                cur_name = line.split(":", 1)[1].strip()
            elif line.startswith("displayName:"):
                cur_disp = line.split(":", 1)[1].strip()
        if cur_name:
            users.append({"name": cur_name, "display_name": cur_disp})

    groups.sort(key=lambda x: x["name"].lower())
    users.sort(key=lambda x: x["name"].lower())
    return {"groups": groups, "users": users}

@router.get("/mappings")
def list_rbac_mappings():
    """Lists all configured Active Directory and user role mappings."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rbac_mappings ORDER BY principal_type ASC, principal_name ASC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"mappings": rows, "count": len(rows)}

@router.post("/mappings")
def create_rbac_mapping(req: RbacMappingCreateRequest):
    """Creates a new role mapping for an Active Directory group or user account."""
    conn = get_db()
    cursor = conn.cursor()
    now = time.time()
    try:
        cursor.execute("""
            INSERT INTO rbac_mappings (principal_type, principal_name, role, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (req.principal_type, req.principal_name.strip(), req.role, req.description, now, now))
        new_id = cursor.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail=f"A mapping for {req.principal_type} '{req.principal_name}' already exists.")
    conn.close()

    log_audit("RBAC_MAPPING_CREATED", "admin", f"{req.principal_type}:{req.principal_name}", "SUCCESS", {"role": req.role})
    return {
        "status": "success",
        "id": new_id,
        "message": f"Mapping created: {req.principal_type} '{req.principal_name}' -> {req.role}."
    }

@router.put("/mappings/{mapping_id}")
def update_rbac_mapping(mapping_id: int, req: RbacMappingUpdateRequest):
    """Updates an existing role mapping."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rbac_mappings WHERE id = ?", (mapping_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Mapping not found.")

    cursor.execute("""
        UPDATE rbac_mappings
        SET role = ?, description = COALESCE(?, description), updated_at = ?
        WHERE id = ?
    """, (req.role, req.description, time.time(), mapping_id))
    conn.commit()
    conn.close()

    log_audit("RBAC_MAPPING_UPDATED", "admin", f"mapping:{mapping_id}", "SUCCESS", {"role": req.role})
    return {"status": "success", "message": "Role mapping updated successfully."}

@router.delete("/mappings/{mapping_id}")
def delete_rbac_mapping(mapping_id: int):
    """Deletes a role mapping."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT principal_name, principal_type FROM rbac_mappings WHERE id = ?", (mapping_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Mapping not found.")

    if row["principal_name"] == "Domain Admins" and row["principal_type"] == "group":
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot delete default 'Domain Admins' mapping to prevent lockout.")

    cursor.execute("DELETE FROM rbac_mappings WHERE id = ?", (mapping_id,))
    conn.commit()
    conn.close()

    log_audit("RBAC_MAPPING_DELETED", "admin", f"{row['principal_type']}:{row['principal_name']}", "SUCCESS", {})
    return {"status": "success", "message": f"Mapping for '{row['principal_name']}' removed."}

@router.get("/me")
def get_my_permissions(authorization: Optional[str] = Header(None)):
    """Returns the authenticated user's current effective role, AD groups, and capability list."""
    current = get_current_user_from_token(authorization)
    username = current["username"]
    role = current["role"]
    perms = ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["readonly"])

    ad_groups = get_user_ad_groups(username)
    return {
        "username": username,
        "role": role,
        "is_ad_user": len(ad_groups) > 0,
        "groups": ad_groups,
        "permissions": perms
    }
