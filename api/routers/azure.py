"""
ZclockID Enterprise Management Appliance - Microsoft Entra ID / Azure AD Cloud Sync Router
Provides automated background identity federation, OAuth 2.0 connectivity diagnostics,
and manual single-shot sync triggers.
"""

from fastapi import APIRouter, HTTPException, status, Depends
import os
import json
import urllib.request
import urllib.parse
from typing import Dict, Any, Optional
from pathlib import Path
from api.core.config import AZURE_CONFIG_FILE, AZURE_STATUS_FILE
from api.services.system_service import run_cmd, log_audit, get_primary_realm
from api.routers.auth import require_role
from api.schemas.azure_schema import AzureSyncConfig, AzureTestConnectionRequest

router = APIRouter(prefix="/api/v1/azure", tags=["Azure / Entra ID Cloud Sync"], dependencies=[Depends(require_role("readonly"))])

@router.get("/status")
def get_azure_sync_status():
    status_data = {
        "status": "NOT_CONFIGURED",
        "enabled": False,
        "last_sync": None,
        "local_users_count": 0,
        "synced_users_count": 0,
        "message": "Azure Cloud Sync has not been initialized."
    }

    if AZURE_CONFIG_FILE.exists():
        try:
            with open(AZURE_CONFIG_FILE) as f:
                cfg = json.load(f)
                status_data["enabled"] = bool(cfg.get("enabled", False))
                if not status_data["enabled"]:
                    status_data["status"] = "DISABLED"
                    status_data["message"] = "Azure sync engine is currently disabled in settings."
                elif cfg.get("tenant_id") and cfg.get("tenant_id") != "YOUR_AZURE_TENANT_ID_GUID":
                    status_data["status"] = "CONFIGURED"
                    status_data["message"] = f"Configured for Entra ID tenant {cfg.get('tenant_id')}."
        except Exception:
            pass

    if AZURE_STATUS_FILE.exists():
        try:
            with open(AZURE_STATUS_FILE) as f:
                st = json.load(f)
                status_data.update(st)
        except Exception:
            pass

    if status_data["local_users_count"] == 0:
        code, out, _ = run_cmd(["samba-tool", "user", "list"])
        if code == 0:
            lines = [l.strip() for l in out.strip().splitlines() if l.strip() and not l.strip().endswith("$")]
            status_data["local_users_count"] = len(lines)

    return status_data

@router.get("/config")
def get_azure_sync_config():
    default_cfg = {
        "enabled": False,
        "tenant_id": "",
        "client_id": "",
        "client_secret": "",
        "default_domain": get_primary_realm().lower() or "",
        "source_ou": "",
        "sync_interval_seconds": 900,
        "exclude_disabled": True,
        "password_hash_sync": False,
        "auto_create_users": True,
        "has_secret": False
    }

    if AZURE_CONFIG_FILE.exists():
        try:
            with open(AZURE_CONFIG_FILE) as f:
                data = json.load(f)
                has_sec = bool(data.get("client_secret") and data["client_secret"] != "YOUR_AZURE_APP_CLIENT_SECRET")
                default_cfg.update(data)
                default_cfg["has_secret"] = has_sec
                if has_sec:
                    default_cfg["client_secret"] = "********"
                else:
                    default_cfg["client_secret"] = ""
        except Exception:
            pass

    return default_cfg

@router.post("/config")
def update_azure_sync_config(cfg: AzureSyncConfig):
    AZURE_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if AZURE_CONFIG_FILE.exists():
        try:
            with open(AZURE_CONFIG_FILE) as f:
                existing = json.load(f)
        except Exception:
            pass

    data = cfg.model_dump()
    if data.get("client_secret") in ["********", "", None] and "client_secret" in existing:
        data["client_secret"] = existing["client_secret"]

    with open(AZURE_CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)

    if cfg.enabled:
        run_cmd(["systemctl", "enable", "--now", "zclock-azuresync"])
    else:
        run_cmd(["systemctl", "stop", "zclock-azuresync"])
        run_cmd(["systemctl", "disable", "zclock-azuresync"])

    log_audit("AZURE_CONFIG_UPDATED", "admin", "azure_sync", "SUCCESS", {
        "tenant_id": cfg.tenant_id,
        "enabled": cfg.enabled,
        "default_domain": cfg.default_domain
    })
    return {"status": "success", "message": "Microsoft Entra ID cloud sync configuration updated successfully."}

@router.post("/test-connection")
def test_azure_connection(req: Optional[AzureTestConnectionRequest] = None):
    tenant_id = req.tenant_id.strip() if req and req.tenant_id else None
    client_id = req.client_id.strip() if req and req.client_id else None
    client_secret = req.client_secret.strip() if req and req.client_secret and req.client_secret != "********" else None

    if not (tenant_id and client_id and client_secret) and AZURE_CONFIG_FILE.exists():
        try:
            with open(AZURE_CONFIG_FILE) as f:
                stored = json.load(f)
                tenant_id = tenant_id or stored.get("tenant_id")
                client_id = client_id or stored.get("client_id")
                client_secret = client_secret or stored.get("client_secret")
        except Exception:
            pass

    if not tenant_id or not client_id or not client_secret or tenant_id == "YOUR_AZURE_TENANT_ID_GUID":
        raise HTTPException(status_code=400, detail="Incomplete credentials. Please provide valid Directory (Tenant) ID, Application (Client) ID, and Client Secret.")

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    post_data = urllib.parse.urlencode({
        "client_id": client_id,
        "scope": "https://graph.microsoft.com/.default",
        "client_secret": client_secret,
        "grant_type": "client_credentials"
    }).encode("utf-8")

    req_obj = urllib.request.Request(token_url, data=post_data, method="POST")
    try:
        with urllib.request.urlopen(req_obj, timeout=12) as resp:
            token_resp = json.loads(resp.read().decode("utf-8"))
            return {
                "success": True,
                "token_type": token_resp.get("token_type", "Bearer"),
                "expires_in": token_resp.get("expires_in", 3600),
                "message": f"Successfully authenticated to Microsoft Entra ID tenant '{tenant_id}'. OAuth 2.0 token verified."
            }
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        try:
            err_json = json.loads(err_body)
            err_desc = err_json.get("error_description", err_body)
        except Exception:
            err_desc = err_body
        return {
            "success": False,
            "status_code": e.code,
            "error": f"Microsoft Entra OAuth Error ({e.code}): {err_desc}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Connection to login.microsoftonline.com failed: {str(e)}"
        }

@router.post("/sync")
def trigger_azure_sync_now():
    script_path = "/zclockid/daemons/zclock-azuresync.py"
    if not os.path.exists(script_path):
        script_path = "/opt/zclockid/scripts/zclock-azuresync.py"

    code, stdout, stderr = run_cmd(["/usr/bin/python3", script_path, "--sync-once"])
    log_audit("AZURE_SYNC_TRIGGERED", "admin", "azure_sync", "SUCCESS" if code == 0 else "FAILED", {"code": code})
    return {
        "status": "success" if code == 0 else "error",
        "exit_code": code,
        "output": stdout.strip(),
        "error": stderr.strip() if code != 0 else None
    }

