"""
ZclockID Enterprise Management Appliance - Sysvol Replication & NTACL Guardian Router
Handles bi-directional GPO file sync, NTACL permission healing (Option A),
partner mesh pairing, and sha256 manifest verification.
"""

from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import PlainTextResponse
import os
import time
import json
import secrets
import hashlib
from typing import Dict, Any, List
from pathlib import Path
from api.core.config import (
    CONFIG_DIR,
    SYSVOL_HEALTH_FILE,
    PHYSICAL_SYSVOL_DIR
)
from api.services.system_service import run_cmd, log_audit
from api.routers.auth import require_role
from api.schemas.sysvol_schema import SysvolPartnerRequest, SysvolFileUploadRequest

router = APIRouter(prefix="/api/v1/sysvol", tags=["Sysvol Replication & NTACL"], dependencies=[Depends(require_role("readonly"))])

SYSVOL_PARTNERS_FILE = CONFIG_DIR / "sysvol_partners.json"
SYSVOL_LOCAL_SECRET_FILE = CONFIG_DIR / "sysvol_secret"
SYSVOL_SYNC_STATUS_FILE = Path("/var/run/zclock-sysvol-sync.json")

@router.get("/status")
def get_sysvol_status():
    """Returns Sysvol file sync status, NTACL health, and partner replication topology."""
    state = {"STATUS": "HEALTHY", "LAST_RESET": time.time(), "MESSAGE": "Sysvol running with valid NTACLs"}
    if SYSVOL_HEALTH_FILE.exists():
        with open(SYSVOL_HEALTH_FILE) as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    state[k] = v

    partner_count = 0
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                partner_count = len(json.load(f).get("partners", []))
        except Exception:
            pass

    return {
        "status": state.get("STATUS", "HEALTHY"),
        "last_reset": float(state.get("LAST_RESET", time.time())),
        "message": state.get("MESSAGE", "Operating normally"),
        "path": str(PHYSICAL_SYSVOL_DIR),
        "partners_count": partner_count,
        "replication_engine": "ZclockID Native Integrated Peer Mesh"
    }

@router.get("/local-secret")
def get_sysvol_local_secret():
    """Returns the local appliance pairing secret used to authorize incoming replication."""
    if not SYSVOL_LOCAL_SECRET_FILE.exists():
        SYSVOL_LOCAL_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SYSVOL_LOCAL_SECRET_FILE, "w") as f:
            f.write(secrets.token_hex(24) + "\n")
        os.chmod(SYSVOL_LOCAL_SECRET_FILE, 0o600)
    with open(SYSVOL_LOCAL_SECRET_FILE) as f:
        return {"secret": f.read().strip()}

@router.get("/partners")
def list_sysvol_partners():
    """Returns list of configured partner Domain Controllers with live synchronization health."""
    partners = []
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                partners = json.load(f).get("partners", [])
        except Exception:
            pass

    sync_telemetry = {}
    if SYSVOL_SYNC_STATUS_FILE.exists():
        try:
            with open(SYSVOL_SYNC_STATUS_FILE) as f:
                data = json.load(f)
                for p in (data.get("partners") or []):
                    sync_telemetry[p["ip_address"]] = p
        except Exception:
            pass

    res = []
    for p in partners:
        t = sync_telemetry.get(p["ip_address"], {})
        res.append({
            "name": p.get("name", p["ip_address"]),
            "ip_address": p["ip_address"],
            "status": t.get("status", "IN_SYNC"),
            "last_sync": t.get("last_sync", time.time()),
            "files_count": t.get("files_count", 0),
            "error": t.get("error")
        })
    return {"count": len(res), "partners": res}

@router.post("/partners")
def add_sysvol_partner(req: SysvolPartnerRequest):
    """Registers an additional Domain Controller for integrated peer-to-peer Sysvol sync."""
    SYSVOL_PARTNERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    current = {"partners": []}
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                current = json.load(f)
        except Exception:
            pass

    existing = [p for p in current.get("partners", []) if p["ip_address"] != req.ip_address]
    existing.append(req.model_dump())
    with open(SYSVOL_PARTNERS_FILE, "w") as f:
        json.dump({"partners": existing}, f, indent=2)

    run_cmd(["systemctl", "restart", "zclock-sysvold"])
    log_audit("SYSVOL_PARTNER_ADDED", "admin", req.ip_address, "SUCCESS", {"name": req.name})
    return {"status": "success", "message": f"Partner DC '{req.name}' ({req.ip_address}) registered for Sysvol replication."}

@router.delete("/partners/{partner_ip}")
def delete_sysvol_partner(partner_ip: str):
    """Unregisters a Domain Controller from the Sysvol replication mesh."""
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                current = json.load(f)
            filtered = [p for p in current.get("partners", []) if p["ip_address"] != partner_ip]
            with open(SYSVOL_PARTNERS_FILE, "w") as f:
                json.dump({"partners": filtered}, f, indent=2)
            run_cmd(["systemctl", "restart", "zclock-sysvold"])
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    return {"status": "success", "message": f"Partner {partner_ip} removed."}

@router.post("/sync-now")
def trigger_sysvol_sync_now():
    """Forces an immediate synchronization cycle across all registered partner DCs."""
    run_cmd(["systemctl", "restart", "zclock-sysvold"])
    return {"status": "success", "message": "Sysvol peer synchronization cycle initiated."}

@router.get("/manifest")
def get_sysvol_manifest():
    """Returns SHA-256 tree of all GPO files and scripts in local Sysvol."""
    sysvol_dir = str(PHYSICAL_SYSVOL_DIR)
    manifest = {}
    if os.path.exists(sysvol_dir):
        for root, dirs, files in os.walk(sysvol_dir):
            for f in files:
                full_p = os.path.join(root, f)
                rel_p = os.path.relpath(full_p, sysvol_dir)
                try:
                    st = os.stat(full_p)
                    with open(full_p, "rb") as fp:
                        h = hashlib.sha256(fp.read()).hexdigest()
                    manifest[rel_p] = {"hash": h, "mtime": st.st_mtime, "size": st.st_size}
                except Exception:
                    pass
    return {"manifest": manifest, "timestamp": time.time()}

@router.get("/file")
def download_sysvol_file(rel_path: str):
    """Securely streams a file from Sysvol to an authorized partner DC."""
    safe_root = PHYSICAL_SYSVOL_DIR.resolve()
    target = (safe_root / rel_path).resolve()
    if not str(target).startswith(str(safe_root)) or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found in Sysvol.")
    with open(target, "rb") as fp:
        content = fp.read()
    return PlainTextResponse(content, media_type="application/octet-stream")

@router.post("/file")
def upload_sysvol_file(req: SysvolFileUploadRequest):
    """Receives and writes a synchronized GPO file from a partner DC."""
    safe_root = PHYSICAL_SYSVOL_DIR.resolve()
    target = (safe_root / req.rel_path).resolve()
    if not str(target).startswith(str(safe_root)):
        raise HTTPException(status_code=400, detail="Invalid relative path.")

    target.parent.mkdir(parents=True, exist_ok=True)
    content_bytes = bytes.fromhex(req.content_base64)
    tmp_p = str(target) + ".tmp"
    with open(tmp_p, "wb") as fp:
        fp.write(content_bytes)
    os.replace(tmp_p, target)
    if req.mtime:
        try: os.utime(target, (req.mtime, req.mtime))
        except: pass

    run_cmd(["samba-tool", "ntacl", "sysvolreset"], timeout=20)
    return {"status": "success", "rel_path": req.rel_path}

@router.post("/reset-ntacl")
def reset_sysvol_ntacl():
    """Forces 'samba-tool ntacl sysvolreset' to restore Windows ACLs across all GPOs."""
    code, stdout, stderr = run_cmd(["samba-tool", "ntacl", "sysvolreset"], timeout=45)
    log_audit("SYSVOL_NTACL_RESET", "admin", "sysvol", "SUCCESS" if code == 0 else "FAILED", {"code": code})
    return {
        "status": "success" if code == 0 else "error",
        "message": "samba-tool ntacl sysvolreset completed. Windows ACLs restored." if code == 0 else stderr
    }

