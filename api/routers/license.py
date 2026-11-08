"""
ZclockID License REST API Router
================================
Provides status, cryptographic validation, upload, and lifecycle management
for ZclockID Enterprise Licenses.
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends, Response
from pydantic import BaseModel

from api.core.license import (
    get_license_status,
    install_license_file,
    remove_installed_license,
    get_license_file_path,
    verify_license_text,
    FREE_TIER_MAX_USERS
)
from api.routers.auth import get_session_user
from api.services.system_service import log_audit, run_cmd
from api.core.config import SAMBA_LDB_PATH

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/license", tags=["License & Subscription"])

def require_admin(user: dict = Depends(get_session_user)) -> dict:
    role = user.get("role", "")
    if role not in ["fulladmin", "admin"]:
        raise HTTPException(status_code=403, detail="Administrative privileges required.")
    return user

class LicenseUploadRequest(BaseModel):
    license_text: str

def get_current_user_count() -> int:
    """Calculates active Active Directory human users (excluding machine/computer accounts)."""
    try:
        code, stdout, _ = run_cmd([
            "ldbsearch", "-H", str(SAMBA_LDB_PATH),
            "(&(objectClass=user)(!(objectClass=computer)))", "sAMAccountName"
        ], timeout=5)
        if code != 0:
            return 0
        count = 0
        for line in stdout.splitlines():
            line_str = line.strip()
            if line_str.startswith("sAMAccountName:") and not line_str.endswith("$"):
                count += 1
        return count
    except Exception as e:
        logger.warning(f"Error querying AD user count: {e}")
        return 0

@router.get("/status")
def get_status():
    """
    Returns current appliance license status, user capacity, validity, and active tier.
    """
    current_users = get_current_user_count()
    status = get_license_status(current_users)
    return status

@router.post("/upload")
async def upload_license(
    file: Optional[UploadFile] = File(None),
    body: Optional[LicenseUploadRequest] = None,
    user: dict = Depends(require_admin)
):
    """
    Uploads and cryptographically validates an official 'zclockid.lic' license certificate.
    """
    raw_content = ""
    if file:
        content_bytes = await file.read()
        try:
            raw_content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="Invalid file encoding. License file must be UTF-8 text.")
    elif body and body.license_text:
        raw_content = body.license_text
    else:
        raise HTTPException(status_code=400, detail="No license file or text provided.")

    success, payload, err = install_license_file(raw_content)
    if not success or not payload:
        raise HTTPException(status_code=400, detail=err or "Invalid license certificate.")

    # Audit logging
    log_audit(
        event_type="LICENSE_INSTALLED",
        actor=user.get("username", "admin"),
        target=payload.get("license_id", "N/A"),
        status="SUCCESS",
        details={
            "organization": payload.get("organization"),
            "max_users": payload.get("max_users"),
            "expiry_date": payload.get("expiry_date"),
            "tier": payload.get("tier")
        }
    )

    current_users = get_current_user_count()
    return {
        "status": "success",
        "message": f"Enterprise license for '{payload.get('organization')}' installed successfully.",
        "license": get_license_status(current_users)
    }

@router.get("/download")
def download_license(user: dict = Depends(require_admin)):
    """Downloads the currently installed zclockid.lic file."""
    lic_path = get_license_file_path()
    if not lic_path.exists():
        raise HTTPException(status_code=404, detail="No custom enterprise license is installed.")

    content = lic_path.read_text(encoding="utf-8")
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="zclockid.lic"'}
    )

@router.delete("/remove")
def remove_license(user: dict = Depends(require_admin)):
    """
    Removes installed license file and reverts appliance to Free Community Tier (up to 200 users).
    """
    removed = remove_installed_license()
    if not removed:
        raise HTTPException(status_code=404, detail="No custom enterprise license to remove.")

    log_audit(
        event_type="LICENSE_REMOVED",
        actor=user.get("username", "admin"),
        target="zclockid.lic",
        status="SUCCESS",
        details={"notice": "Reverted to Free Community Tier (up to 200 users)."}
    )

    current_users = get_current_user_count()
    return {
        "status": "success",
        "message": "Enterprise license removed. Appliance reverted to Free Community Tier.",
        "license": get_license_status(current_users)
    }
