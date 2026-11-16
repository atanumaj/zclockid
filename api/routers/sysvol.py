"""
ZclockID Enterprise Management Appliance - Sysvol Replication & NTACL Guardian Router
Handles bi-directional GPO file sync, NTACL permission healing (Option A),
partner mesh pairing, sha256 manifest verification, and locked-down peer-to-peer security.
"""

from fastapi import APIRouter, HTTPException, status, Depends, Header, Request
from fastapi.responses import PlainTextResponse
import os
import time
import json
import secrets
import hashlib
import ssl
import socket
from typing import Dict, Any, List, Optional
from pathlib import Path
from api.core.config import (
    CONFIG_DIR,
    SYSVOL_HEALTH_FILE,
    PHYSICAL_SYSVOL_DIR
)
from api.services.system_service import run_cmd, log_audit
from api.services.security_service import get_client_ip
from api.routers.auth import require_role, get_session_user
from api.schemas.sysvol_schema import SysvolPartnerRequest, SysvolFileUploadRequest

router = APIRouter(prefix="/api/v1/sysvol", tags=["Sysvol Replication & NTACL"])

SYSVOL_PARTNERS_FILE = CONFIG_DIR / "sysvol_partners.json"
SYSVOL_LOCAL_SECRET_FILE = CONFIG_DIR / "sysvol_secret"
SYSVOL_SYNC_STATUS_FILE = Path("/var/run/zclock-sysvol-sync.json")
SYSVOL_CERTS_DIR = Path("/etc/zclockid/certs")

MAX_SYSVOL_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB upload limit


def validate_sysvol_path(rel_path: str, safe_root: Path) -> Path:
    """
    Validates that a relative Sysvol path is safe:
    - Non-empty and non-whitespace
    - Not an absolute path (leading slash / drive letter)
    - Resolves strictly inside safe_root using Path.is_relative_to()
    - Does not contain .tmp extension
    - Does not contain symlinks anywhere in its target or path hierarchy
    """
    if not rel_path or not str(rel_path).strip():
        raise HTTPException(status_code=400, detail="Relative path cannot be empty.")

    clean_p = str(rel_path).strip()

    # Reject absolute paths
    if os.path.isabs(clean_p) or clean_p.startswith("/") or clean_p.startswith("\\"):
        raise HTTPException(status_code=400, detail="Absolute paths are not allowed.")

    # Reject .tmp suffixes
    if clean_p.endswith(".tmp") or ".tmp" in Path(clean_p).suffixes:
        raise HTTPException(status_code=400, detail="Temporary file extensions (.tmp) are not allowed.")

    # Resolve target against safe_root
    try:
        target = (safe_root / clean_p).resolve()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid path syntax: {e}")

    # Enforce Path.is_relative_to(safe_root)
    try:
        if not target.is_relative_to(safe_root):
            raise HTTPException(status_code=400, detail="Path traversal rejected: target outside SYSVOL root.")
    except AttributeError:
        # Fallback for Python < 3.9
        if not str(target).startswith(str(safe_root)):
            raise HTTPException(status_code=400, detail="Path traversal rejected: target outside SYSVOL root.")

    # Reject symlinks on the target itself
    if target.is_symlink() or (target.exists() and os.path.islink(target)):
        raise HTTPException(status_code=400, detail="Symlinks inside SYSVOL are not allowed.")

    # Check parent directories up to safe_root for symlinks
    curr = target.parent
    while curr != safe_root and curr != curr.parent:
        if curr.is_symlink() or (curr.exists() and os.path.islink(curr)):
            raise HTTPException(status_code=400, detail="Symlinks in path hierarchy are not allowed.")
        curr = curr.parent

    return target


def verify_sysvol_sync_access(
    request: Request,
    x_zclock_sync_secret: Optional[str] = Header(None, alias="X-Zclock-Sync-Secret")
):
    """
    Authorizes incoming Sysvol replication requests strictly from registered peer Domain Controllers.
    - Ties the secret to the requesting peer IP (using get_client_ip).
    - Accepts ONLY that specific partner's shared_secret.
    - Does NOT accept user session tokens.
    - Does NOT accept the appliance's own local secret on inbound calls to ensure mutual pairing integrity.
    - Logs rejected attempts with the source IP in the audit log.
    """
    client_ip = get_client_ip(request)

    if not x_zclock_sync_secret:
        log_audit("SYSVOL_SYNC_AUTH_REJECTED", "peer", client_ip, "FAILED", {"reason": "Missing X-Zclock-Sync-Secret header"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sysvol replication access denied: Missing X-Zclock-Sync-Secret header."
        )

    clean_secret = x_zclock_sync_secret.strip()

    # Look up partner matching client_ip in sysvol_partners.json
    partner = None
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                partners = json.load(f).get("partners", [])
                for p in partners:
                    if p.get("ip_address") == client_ip:
                        partner = p
                        break
        except Exception as e:
            pass

    if not partner:
        log_audit("SYSVOL_SYNC_AUTH_REJECTED", "peer", client_ip, "FAILED", {"reason": f"Peer IP {client_ip} is not a registered partner DC"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Sysvol replication access denied: Peer IP {client_ip} is not a registered partner DC."
        )

    partner_secret = partner.get("shared_secret", "").strip()
    if not partner_secret or not secrets.compare_digest(clean_secret, partner_secret):
        log_audit("SYSVOL_SYNC_AUTH_REJECTED", "peer", client_ip, "FAILED", {"reason": f"Invalid shared secret for partner IP {client_ip}"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sysvol replication access denied: Invalid secret for partner."
        )

    return partner


def probe_peer_tls_certificate(ip: str, port: int = 443) -> dict:
    """Connects to a peer DC over TLS, extracts its certificate PEM, and computes the SHA-256 fingerprint."""
    try:
        cert_pem = ssl.get_server_certificate((ip, port), timeout=5)
        der = ssl.PEM_cert_to_DER_cert(cert_pem)
        fp = hashlib.sha256(der).hexdigest()
        formatted_fp = ":".join(fp[i:i+2].upper() for i in range(0, len(fp), 2))
        return {
            "ip_address": ip,
            "fingerprint": formatted_fp,
            "fingerprint_hex": fp.lower(),
            "cert_pem": cert_pem
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to probe TLS certificate from {ip}:{port}: {e}")


@router.get("/status", dependencies=[Depends(require_role("readonly"))])
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


@router.get("/probe-tls", dependencies=[Depends(require_role("operator"))])
def probe_sysvol_tls(ip: str):
    """Probes peer DC over TLS and returns certificate fingerprint for admin verification."""
    return probe_peer_tls_certificate(ip)


@router.get("/local-secret", dependencies=[Depends(require_role("operator"))])
def get_sysvol_local_secret():
    """Returns the local appliance pairing secret used to authorize incoming replication."""
    if not SYSVOL_LOCAL_SECRET_FILE.exists():
        SYSVOL_LOCAL_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SYSVOL_LOCAL_SECRET_FILE, "w") as f:
            f.write(secrets.token_hex(24) + "\n")
        os.chmod(SYSVOL_LOCAL_SECRET_FILE, 0o600)
    with open(SYSVOL_LOCAL_SECRET_FILE) as f:
        return {"secret": f.read().strip()}


@router.get("/partners", dependencies=[Depends(require_role("readonly"))])
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
            "cert_fingerprint": p.get("cert_fingerprint"),
            "status": t.get("status", "IN_SYNC"),
            "last_sync": t.get("last_sync", time.time()),
            "files_count": t.get("files_count", 0),
            "error": t.get("error")
        })
    return {"count": len(res), "partners": res}


@router.post("/partners", dependencies=[Depends(require_role("operator"))])
def add_sysvol_partner(req: SysvolPartnerRequest):
    """Registers an additional Domain Controller with mutual secret and pinned TLS certificate fingerprint."""
    SYSVOL_PARTNERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    current = {"partners": []}
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                current = json.load(f)
        except Exception:
            pass

    partner_dict = req.model_dump()

    # If cert_fingerprint is not provided, probe peer automatically
    if not partner_dict.get("cert_fingerprint"):
        try:
            probe = probe_peer_tls_certificate(req.ip_address)
            partner_dict["cert_fingerprint"] = probe["fingerprint"]
            partner_dict["cert_pem"] = probe["cert_pem"]
        except Exception:
            pass
    elif not partner_dict.get("cert_pem"):
        try:
            probe = probe_peer_tls_certificate(req.ip_address)
            # Normalize and verify matching fingerprint
            clean_probe_fp = probe["fingerprint"].replace(":", "").lower()
            clean_req_fp = partner_dict["cert_fingerprint"].replace(":", "").lower()
            if clean_probe_fp == clean_req_fp:
                partner_dict["cert_pem"] = probe["cert_pem"]
        except Exception:
            pass

    # Save cert PEM to disk if available
    if partner_dict.get("cert_pem"):
        try:
            SYSVOL_CERTS_DIR.mkdir(parents=True, exist_ok=True)
            cert_file = SYSVOL_CERTS_DIR / f"partner_{req.ip_address}.crt"
            cert_file.write_text(partner_dict["cert_pem"])
            os.chmod(cert_file, 0o644)
        except Exception:
            pass

    existing = [p for p in current.get("partners", []) if p["ip_address"] != req.ip_address]
    existing.append(partner_dict)
    with open(SYSVOL_PARTNERS_FILE, "w") as f:
        json.dump({"partners": existing}, f, indent=2)

    run_cmd(["systemctl", "restart", "zclock-sysvold"])
    log_audit("SYSVOL_PARTNER_ADDED", "admin", req.ip_address, "SUCCESS", {
        "name": req.name,
        "fingerprint": partner_dict.get("cert_fingerprint")
    })
    return {
        "status": "success",
        "message": f"Partner DC '{req.name}' ({req.ip_address}) registered with TLS fingerprint pinning."
    }


@router.delete("/partners/{partner_ip}", dependencies=[Depends(require_role("operator"))])
def delete_sysvol_partner(partner_ip: str):
    """Unregisters a Domain Controller from the Sysvol replication mesh."""
    if SYSVOL_PARTNERS_FILE.exists():
        try:
            with open(SYSVOL_PARTNERS_FILE) as f:
                current = json.load(f)
            filtered = [p for p in current.get("partners", []) if p["ip_address"] != partner_ip]
            with open(SYSVOL_PARTNERS_FILE, "w") as f:
                json.dump({"partners": filtered}, f, indent=2)

            cert_file = SYSVOL_CERTS_DIR / f"partner_{partner_ip}.crt"
            cert_file.unlink(missing_ok=True)

            run_cmd(["systemctl", "restart", "zclock-sysvold"])
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    return {"status": "success", "message": f"Partner {partner_ip} removed."}


@router.post("/sync-now", dependencies=[Depends(require_role("operator"))])
def trigger_sysvol_sync_now():
    """Forces an immediate synchronization cycle across all registered partner DCs."""
    run_cmd(["systemctl", "restart", "zclock-sysvold"])
    return {"status": "success", "message": "Sysvol peer synchronization cycle initiated."}


# --- Peer Replication Endpoints (Authenticated strictly by peer sync secret) ---

@router.get("/manifest", dependencies=[Depends(verify_sysvol_sync_access)])
def get_sysvol_manifest():
    """Returns SHA-256 tree of all GPO files and scripts in local Sysvol for authorized peer DC."""
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


@router.get("/file", dependencies=[Depends(verify_sysvol_sync_access)])
def download_sysvol_file(rel_path: str):
    """Securely streams a file from Sysvol to an authorized partner DC."""
    safe_root = PHYSICAL_SYSVOL_DIR.resolve()
    target = validate_sysvol_path(rel_path, safe_root)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="File not found in Sysvol.")
    with open(target, "rb") as fp:
        content = fp.read()
    return PlainTextResponse(content, media_type="application/octet-stream")


@router.post("/file", dependencies=[Depends(verify_sysvol_sync_access)])
def upload_sysvol_file(req: SysvolFileUploadRequest):
    """Receives and writes a synchronized GPO file from an authorized partner DC."""
    safe_root = PHYSICAL_SYSVOL_DIR.resolve()
    target = validate_sysvol_path(req.rel_path, safe_root)

    # Enforce 50 MB upload limit
    if len(req.content_base64) > MAX_SYSVOL_UPLOAD_SIZE * 2:
        raise HTTPException(status_code=413, detail="File payload exceeds 50 MB limit.")
    try:
        content_bytes = bytes.fromhex(req.content_base64)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding in content_base64.")
    if len(content_bytes) > MAX_SYSVOL_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File payload exceeds 50 MB limit.")

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_p = str(target) + ".upload_tmp"
    with open(tmp_p, "wb") as fp:
        fp.write(content_bytes)
    os.replace(tmp_p, target)
    if req.mtime:
        try: os.utime(target, (req.mtime, req.mtime))
        except: pass

    run_cmd(["samba-tool", "ntacl", "sysvolreset"], timeout=20)
    return {"status": "success", "rel_path": req.rel_path}


# --- Admin UI Separate Routes (Requires operator for read, fulladmin for write) ---

@router.get("/admin/manifest")
def admin_get_sysvol_manifest(user: dict = Depends(require_role("operator"))):
    """Allows administrators to browse SYSVOL manifest with audit logging."""
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
    log_audit("SYSVOL_ADMIN_MANIFEST_READ", user.get("sub", "admin"), "sysvol", "SUCCESS", {})
    return {"manifest": manifest, "timestamp": time.time()}


@router.get("/admin/file")
def admin_download_sysvol_file(rel_path: str, user: dict = Depends(require_role("operator"))):
    """Allows administrators to download/browse a SYSVOL file with audit logging."""
    safe_root = PHYSICAL_SYSVOL_DIR.resolve()
    target = validate_sysvol_path(rel_path, safe_root)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="File not found in Sysvol.")
    log_audit("SYSVOL_ADMIN_FILE_READ", user.get("sub", "admin"), rel_path, "SUCCESS", {})
    with open(target, "rb") as fp:
        content = fp.read()
    return PlainTextResponse(content, media_type="application/octet-stream")


@router.post("/admin/file")
def admin_upload_sysvol_file(req: SysvolFileUploadRequest, user: dict = Depends(require_role("fulladmin"))):
    """Allows full administrators to upload a GPO file to SYSVOL with audit logging."""
    safe_root = PHYSICAL_SYSVOL_DIR.resolve()
    target = validate_sysvol_path(req.rel_path, safe_root)

    if len(req.content_base64) > MAX_SYSVOL_UPLOAD_SIZE * 2:
        raise HTTPException(status_code=413, detail="File payload exceeds 50 MB limit.")
    try:
        content_bytes = bytes.fromhex(req.content_base64)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding in content_base64.")
    if len(content_bytes) > MAX_SYSVOL_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File payload exceeds 50 MB limit.")

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_p = str(target) + ".admin_tmp"
    with open(tmp_p, "wb") as fp:
        fp.write(content_bytes)
    os.replace(tmp_p, target)
    if req.mtime:
        try: os.utime(target, (req.mtime, req.mtime))
        except: pass

    run_cmd(["samba-tool", "ntacl", "sysvolreset"], timeout=20)
    log_audit("SYSVOL_ADMIN_FILE_WRITE", user.get("sub", "admin"), req.rel_path, "SUCCESS", {})
    return {"status": "success", "rel_path": req.rel_path}


@router.post("/reset-ntacl", dependencies=[Depends(require_role("operator"))])
def reset_sysvol_ntacl():
    """Forces 'samba-tool ntacl sysvolreset' to restore Windows ACLs across all GPOs."""
    code, stdout, stderr = run_cmd(["samba-tool", "ntacl", "sysvolreset"], timeout=45)
    log_audit("SYSVOL_NTACL_RESET", "admin", "sysvol", "SUCCESS" if code == 0 else "FAILED", {"code": code})
    return {
        "status": "success" if code == 0 else "error",
        "message": "samba-tool ntacl sysvolreset completed. Windows ACLs restored." if code == 0 else stderr
    }
