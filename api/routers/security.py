"""
ZclockID System Security & Access Baseline API Router
Provides administrative endpoints for session timeout, brute-force protection, CIDR network ACLs, OpenSSH and SNMP baselines.
"""

import time
import sqlite3
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Header, Request, status

from api.core.config import DB_PATH
from api.routers.auth import get_session_user
from api.schemas.security_schema import (
    SecuritySettingsUpdateRequest,
    SecuritySettingsResponse,
    ActiveSessionItem
)
from api.schemas.firewall_schema import (
    FirewallToggleRequest,
    FirewallRuleRequest,
    FirewallRuleToggleRequest
)
from api.services.system_service import check_systemd_service, log_audit
from api.services.security_service import (
    get_client_ip,
    validate_subnets_syntax,
    is_ip_allowed,
    get_security_settings,
    apply_ssh_hardening,
    apply_snmp_hardening
)
from api.services.firewall_service import (
    get_firewall_status,
    toggle_firewall_state,
    add_custom_rule,
    update_rule,
    delete_rule,
    toggle_rule,
    apply_firewall,
    reset_to_default_template
)

router = APIRouter(prefix="/api/v1/security", tags=["System Security & Access Controls"])

def require_admin(authorization: Optional[str] = Header(None)) -> dict:
    user = get_session_user(authorization)
    if user.get("role") != "fulladmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Full Administrator privileges required."
        )
    return user

@router.get("/settings", response_model=SecuritySettingsResponse)
def get_security_baseline_settings(request: Request, user: dict = Depends(get_session_user)):
    """Retrieves system-wide security baseline policies, current client IP, and daemon states."""
    settings = get_security_settings()
    client_ip = get_client_ip(request)

    ssh_stat = check_systemd_service("ssh")
    snmp_stat = check_systemd_service("snmpd")

    return SecuritySettingsResponse(
        session_idle_timeout_min=settings.get("session_idle_timeout_min", 15),
        session_max_lifetime_hours=settings.get("session_max_lifetime_hours", 8),
        allowed_subnets_gui=settings.get("allowed_subnets_gui", "0.0.0.0/0, ::/0"),
        allowed_subnets_ssh=settings.get("allowed_subnets_ssh", "0.0.0.0/0, ::/0"),
        allowed_subnets_snmp=settings.get("allowed_subnets_snmp", "192.168.1.0/24, 10.10.0.0/24, 127.0.0.1/32"),
        snmp_community=settings.get("snmp_community", "zclock_public"),
        max_failed_logins=settings.get("max_failed_logins", 5),
        lockout_duration_min=settings.get("lockout_duration_min", 15),
        ssh_permit_root=settings.get("ssh_permit_root", 0),
        ssh_password_auth=settings.get("ssh_password_auth", 1),
        updated_at=settings.get("updated_at", time.time()),
        current_client_ip=client_ip,
        ssh_service_active=ssh_stat.get("status") == "active",
        snmp_service_active=snmp_stat.get("status") == "active"
    )

@router.put("/settings")
def update_security_baseline_settings(
    req: SecuritySettingsUpdateRequest,
    request: Request,
    user: dict = Depends(require_admin)
):
    """
    Updates system-wide security baselines with automated anti-lockout safety verification.
    Applies OpenSSH and SNMP controls natively across the OS.
    """
    client_ip = get_client_ip(request)

    # 1. Syntax validation of CIDRs
    for name, subnets in [
        ("Web GUI / REST API", req.allowed_subnets_gui),
        ("SSH", req.allowed_subnets_ssh),
        ("SNMP", req.allowed_subnets_snmp)
    ]:
        valid, err = validate_subnets_syntax(subnets)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Syntax error in {name} CIDR: {err}")

    # 2. Safety Check: GUI Admin Lockout Prevention
    if not is_ip_allowed(client_ip, req.allowed_subnets_gui):
        raise HTTPException(
            status_code=400,
            detail=f"Lockout Prevention Guard: Your current client IP ({client_ip}) would be immediately blocked from accessing the Web GUI & REST API. Include your IP or subnet in the allowed list."
        )

    # 3. Safety Check: SSH Admin Lockout Prevention
    if not is_ip_allowed(client_ip, req.allowed_subnets_ssh):
        raise HTTPException(
            status_code=400,
            detail=f"Lockout Prevention Guard: Your current client IP ({client_ip}) would be immediately blocked from SSH access. Include your IP or subnet in the SSH allowed list."
        )

    # 4. Persist to SQLite
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE security_settings SET
            session_idle_timeout_min = ?,
            session_max_lifetime_hours = ?,
            allowed_subnets_gui = ?,
            allowed_subnets_ssh = ?,
            allowed_subnets_snmp = ?,
            snmp_community = ?,
            max_failed_logins = ?,
            lockout_duration_min = ?,
            ssh_permit_root = ?,
            ssh_password_auth = ?,
            updated_at = ?
        WHERE id = 1
    """, (
        req.session_idle_timeout_min,
        req.session_max_lifetime_hours,
        req.allowed_subnets_gui.strip(),
        req.allowed_subnets_ssh.strip(),
        req.allowed_subnets_snmp.strip(),
        req.snmp_community.strip(),
        req.max_failed_logins,
        req.lockout_duration_min,
        req.ssh_permit_root,
        req.ssh_password_auth,
        now
    ))
    conn.commit()
    conn.close()

    # 5. Apply OS level OpenSSH hardening
    ssh_ok, ssh_msg = apply_ssh_hardening(req.allowed_subnets_ssh, req.ssh_permit_root, req.ssh_password_auth)

    # 6. Apply SNMP access controls
    snmp_ok, snmp_msg = apply_snmp_hardening(req.allowed_subnets_snmp, req.snmp_community)

    log_audit("SECURITY_BASELINE_UPDATED", user["username"], "system_security", "SUCCESS", {
        "idle_timeout_min": req.session_idle_timeout_min,
        "allowed_subnets_gui": req.allowed_subnets_gui,
        "allowed_subnets_ssh": req.allowed_subnets_ssh,
        "allowed_subnets_snmp": req.allowed_subnets_snmp,
        "ssh_status": ssh_msg,
        "snmp_status": snmp_msg
    })

    return {
        "status": "success",
        "message": "System security controls and network baseline updated successfully.",
        "ssh_result": ssh_msg,
        "snmp_result": snmp_msg
    }

@router.get("/sessions", response_model=List[ActiveSessionItem])
def list_active_sessions(
    request: Request,
    authorization: Optional[str] = Header(None),
    user: dict = Depends(get_session_user)
):
    """Lists all active administrative sessions."""
    current_token = authorization.replace("Bearer ", "").strip() if authorization else ""
    now = time.time()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT token, username, role, ip_address, user_agent, created_at, last_active, expires_at
        FROM sessions
        WHERE expires_at > ?
        ORDER BY last_active DESC
    """, (now,))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        tok = r["token"]
        is_cur = (tok == current_token)
        prefix = tok[:8] + "..." + tok[-4:]
        results.append(ActiveSessionItem(
            token_prefix=prefix,
            username=r["username"],
            role=r["role"],
            ip_address=r["ip_address"] or "unknown",
            user_agent=r["user_agent"] or "unknown",
            created_at=r["created_at"],
            last_active=r["last_active"] or r["created_at"],
            is_current=is_cur
        ))
    return results

@router.delete("/sessions/{token_prefix}")
def terminate_session(
    token_prefix: str,
    authorization: Optional[str] = Header(None),
    user: dict = Depends(require_admin)
):
    """Terminates an administrative session by prefix."""
    current_token = authorization.replace("Bearer ", "").strip() if authorization else ""
    prefix_clean = token_prefix.split("...")[0]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT token, username FROM sessions WHERE token LIKE ?", (f"{prefix_clean}%",))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Session not found.")

    tok, uname = row
    if tok == current_token:
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot terminate your own current active session from this view.")

    cursor.execute("DELETE FROM sessions WHERE token = ?", (tok,))
    conn.commit()
    conn.close()

    log_audit("ADMIN_SESSION_TERMINATED", user["username"], uname, "SUCCESS", {"token_prefix": token_prefix})
    return {"status": "success", "message": f"Session for user '{uname}' terminated successfully."}

@router.post("/sessions/terminate-others")
def terminate_all_other_sessions(
    authorization: Optional[str] = Header(None),
    user: dict = Depends(require_admin)
):
    """Terminates all active administrative sessions except the caller's current session."""
    current_token = authorization.replace("Bearer ", "").strip() if authorization else ""
    if not current_token:
        raise HTTPException(status_code=400, detail="Current token missing.")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE token != ?", (current_token,))
    terminated_count = cursor.rowcount
    conn.commit()
    conn.close()

    log_audit("ALL_OTHER_SESSIONS_TERMINATED", user["username"], "all_sessions", "SUCCESS", {"terminated": terminated_count})
    return {"status": "success", "message": f"Successfully revoked {terminated_count} other active session(s)."}


# ----------------- Appliance Host Firewall & Port Protection -----------------

@router.get("/firewall/status")
def get_firewall_overview(user: dict = Depends(require_admin)):
    """Returns stored firewall configuration, custom/system rules, and live enforcement state."""
    return get_firewall_status()

@router.post("/firewall/toggle")
def toggle_firewall(req: FirewallToggleRequest, user: dict = Depends(require_admin)):
    """Switches the host firewall master state ON or OFF."""
    state = req.target_state()
    success, msg = toggle_firewall_state(state)
    if not success:
        raise HTTPException(status_code=500, detail=msg)
    log_audit("FIREWALL_TOGGLE", user["username"], "ufw", "SUCCESS", {"state": state})
    return {"status": "success", "is_enabled": state, "message": msg}

@router.post("/firewall/rules")
def create_firewall_rule(req: FirewallRuleRequest, user: dict = Depends(require_admin)):
    """Adds a new custom firewall rule (ALLOW / DENY) and applies it to kernel netfilter."""
    try:
        rule_id = add_custom_rule(
            action=req.action,
            protocol=req.protocol,
            port=req.port,
            source=req.source,
            comment=req.comment or "",
            is_enabled=req.is_enabled
        )
        return {"status": "success", "rule_id": rule_id, "message": "Firewall rule created and applied successfully."}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add rule: {str(e)}")

@router.put("/firewall/rules/{rule_id}")
def update_firewall_rule(rule_id: int, req: FirewallRuleRequest, user: dict = Depends(require_admin)):
    """Updates an existing firewall rule and re-applies policies."""
    try:
        success = update_rule(
            rule_id=rule_id,
            action=req.action,
            protocol=req.protocol,
            port=req.port,
            source=req.source,
            comment=req.comment or "",
            is_enabled=req.is_enabled
        )
        if not success:
            raise HTTPException(status_code=404, detail="Rule not found.")
        return {"status": "success", "message": "Firewall rule updated and re-applied successfully."}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update rule: {str(e)}")

@router.delete("/firewall/rules/{rule_id}")
def delete_firewall_rule(rule_id: int, user: dict = Depends(require_admin)):
    """Deletes a custom firewall rule."""
    try:
        success = delete_rule(rule_id)
        if not success:
            raise HTTPException(status_code=404, detail="Rule not found.")
        return {"status": "success", "message": "Firewall rule deleted successfully."}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete rule: {str(e)}")

@router.post("/firewall/rules/{rule_id}/toggle")
def toggle_firewall_rule(rule_id: int, req: FirewallRuleToggleRequest, user: dict = Depends(require_admin)):
    """Toggles a rule enabled or disabled."""
    success = toggle_rule(rule_id, req.is_enabled)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found.")
    return {"status": "success", "message": f"Rule state toggled to {'enabled' if req.is_enabled else 'disabled'}."}

@router.post("/firewall/apply")
def force_reapply_firewall(user: dict = Depends(require_admin)):
    """Forces complete synchronization between database rules and the Linux kernel firewall."""
    success, msg = apply_firewall()
    if not success:
        raise HTTPException(status_code=500, detail=msg)
    return {"status": "success", "message": msg}

@router.post("/firewall/reset-template")
def reset_firewall_rules_template(user: dict = Depends(require_admin)):
    """Wipes all current rules and resets to the factory recommended template required for ZclockID domain controller functions."""
    try:
        success, msg = reset_to_default_template()
        if not success:
            raise HTTPException(status_code=500, detail=msg)
        log_audit("FIREWALL_RESET_TEMPLATE", user["username"], "ufw", "SUCCESS", {})
        return {"status": "success", "message": "Firewall rules reset to recommended baseline template."}
    except Exception as e:
        log_audit("FIREWALL_RESET_TEMPLATE", user["username"], "ufw", "FAILED", {"error": str(e)})
        raise HTTPException(status_code=500, detail=f"Failed to reset rules template: {str(e)}")

