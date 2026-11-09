"""
ZclockID License Verification & Capacity Subsystem
==================================================
Manages cryptographically signed 'zclockid.lic' enterprise licenses.
Free for general use up to 200 users; requires an active license certificate above 200 users.
Uses asymmetric Ed25519 digital signature verification.

Author & Copyright (c) 2026 Atanu Majumdar (@atanumaj). All Rights Reserved.
"""

__author__ = "Atanu Majumdar (@atanumaj)"
__copyright__ = "Copyright (c) 2026 Atanu Majumdar. All Rights Reserved."
__license__ = "ZclockID Commercial & Community License"
LICENSE_FINGERPRINT = "ZCLOCKID-ATANUMAJ-ED25519-2026"

import os
import json
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Embedded Public Key (fallback if external file missing)
EMBEDDED_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPutLXa/GbxfiYZxrs0ZFMsIuaeJbJNc+RfOjtqYPXOU=
-----END PUBLIC KEY-----
"""

FREE_TIER_MAX_USERS = 200
PRIMARY_LICENSE_PATH = Path("/etc/zclockid/license/zclockid.lic")
FALLBACK_LICENSE_PATHS = [
    Path("/opt/zclockid/license/zclockid.lic")
]

def get_license_file_path() -> Path:
    """Returns the active license file path."""
    if PRIMARY_LICENSE_PATH.exists():
        return PRIMARY_LICENSE_PATH
    for fb in FALLBACK_LICENSE_PATHS:
        if fb.exists():
            return fb
    return PRIMARY_LICENSE_PATH

def load_public_key() -> ed25519.Ed25519PublicKey:
    """Loads the master Ed25519 public key."""
    key_path = Path(__file__).resolve().parent / "license_public_key.pem"
    pem_bytes = EMBEDDED_PUBLIC_KEY_PEM
    if key_path.exists():
        try:
            pem_bytes = key_path.read_bytes()
        except Exception:
            pem_bytes = EMBEDDED_PUBLIC_KEY_PEM

    return serialization.load_pem_public_key(pem_bytes)

def verify_license_text(license_text: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Cryptographically verifies the authenticity and integrity of a zclockid.lic text.
    Returns (is_valid, payload, error_message).
    """
    if not license_text or not license_text.strip():
        return False, None, "Empty license file."

    clean_text = license_text.strip()
    # Check headers
    if "-----BEGIN ZCLOCKID LICENSE-----" in clean_text:
        clean_text = clean_text.replace("-----BEGIN ZCLOCKID LICENSE-----", "")
    if "-----END ZCLOCKID LICENSE-----" in clean_text:
        clean_text = clean_text.replace("-----END ZCLOCKID LICENSE-----", "")

    # Remove all whitespace/newlines
    token_str = "".join(clean_text.split())

    if "." not in token_str:
        return False, None, "Invalid license format (missing payload-signature delimiter)."

    parts = token_str.split(".", 1)
    payload_b64 = parts[0]
    sig_b64 = parts[1]

    try:
        payload_bytes = base64.b64decode(payload_b64)
        sig_bytes = base64.b64decode(sig_b64)
    except Exception as e:
        return False, None, f"Malformed Base64 in license: {str(e)}"

    # Asymmetric signature verification
    try:
        pub_key = load_public_key()
        pub_key.verify(sig_bytes, payload_bytes)
    except InvalidSignature:
        return False, None, "Cryptographic signature verification failed. The license has been forged or altered."
    except Exception as e:
        return False, None, f"Signature verification error: {str(e)}"

    # Parse JSON payload
    try:
        payload = json.loads(payload_bytes.decode('utf-8'))
    except Exception as e:
        return False, None, f"Corrupted license payload JSON: {str(e)}"

    # Validate essential fields
    required_fields = ["license_id", "organization", "max_users", "expiry_date"]
    for field in required_fields:
        if field not in payload:
            return False, None, f"Missing required license parameter: '{field}'."

    return True, payload, None

def get_license_status(current_user_count: int) -> Dict[str, Any]:
    """
    Evaluates the active appliance license state against current Active Directory user count.
    """
    lic_path = get_license_file_path()
    raw_license = ""
    if lic_path.exists():
        try:
            raw_license = lic_path.read_text(encoding="utf-8").strip()
        except Exception:
            raw_license = ""

    now_utc = datetime.now(timezone.utc)
    today_str = now_utc.strftime("%Y-%m-%d")

    # If no license installed -> Free Community Tier (up to 200 users)
    if not raw_license:
        max_users = FREE_TIER_MAX_USERS
        can_create = current_user_count < max_users
        utilization = round((current_user_count / max_users) * 100, 1) if max_users > 0 else 0
        return {
            "tier": "Community Edition",
            "is_licensed": False,
            "status": "FREE_TIER",
            "status_label": "Community Free Tier (Up to 200 Users)",
            "is_valid": True,
            "organization": "Community / General Use",
            "license_id": "COMMUNITY-TIER-200",
            "max_users": max_users,
            "is_unlimited": False,
            "current_users": current_user_count,
            "remaining_capacity": max(0, max_users - current_user_count),
            "utilization_pct": min(100.0, utilization),
            "issued_date": "N/A",
            "expiry_date": "PERPETUAL",
            "is_perpetual": True,
            "days_remaining": None,
            "can_create_user": can_create,
            "over_limit": current_user_count > max_users,
            "author": "Atanu Majumdar (@atanumaj)",
            "author_url": "https://github.com/atanumaj",
            "copyright": "Copyright (c) 2026 Atanu Majumdar. All Rights Reserved.",
            "notice": "Appliance is operating under the free Community tier (up to 200 users). A signed license is required for deployments exceeding 200 users."
        }

    # Verify custom installed license
    is_valid, payload, err = verify_license_text(raw_license)
    if not is_valid:
        # Invalid signature or corrupted license -> Revert capacity to Free Tier
        max_users = FREE_TIER_MAX_USERS
        can_create = current_user_count < max_users
        utilization = round((current_user_count / max_users) * 100, 1) if max_users > 0 else 0
        return {
            "tier": "Invalid License",
            "is_licensed": False,
            "status": "INVALID_SIGNATURE",
            "status_label": "Invalid or Tampered License",
            "is_valid": False,
            "error_detail": err,
            "organization": "Unknown",
            "license_id": "INVALID",
            "max_users": max_users,
            "is_unlimited": False,
            "current_users": current_user_count,
            "remaining_capacity": max(0, max_users - current_user_count),
            "utilization_pct": min(100.0, utilization),
            "issued_date": "N/A",
            "expiry_date": "INVALID",
            "is_perpetual": False,
            "days_remaining": 0,
            "can_create_user": can_create,
            "over_limit": current_user_count > max_users,
            "notice": f"Installed license verification failed: {err}. Reverted to Free Community limit (200 users)."
        }

    # Check expiration
    is_perpetual = payload.get("is_perpetual", False) or payload.get("expiry_date") == "PERPETUAL"
    expiry_date_str = payload.get("expiry_date", "")
    days_remaining: Optional[int] = None
    is_expired = False

    if not is_perpetual:
        try:
            exp_dt = datetime.strptime(expiry_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            delta = exp_dt - now_utc
            days_remaining = max(0, delta.days)
            if delta.total_seconds() < 0:
                is_expired = True
        except Exception:
            is_expired = True
            days_remaining = 0

    max_users = payload.get("max_users", 500)
    is_unlimited = (max_users == 0)

    if is_expired:
        # Expired license -> Reverts capacity to Free Tier
        effective_max = FREE_TIER_MAX_USERS
        can_create = current_user_count < effective_max
        utilization = round((current_user_count / effective_max) * 100, 1) if effective_max > 0 else 0
        return {
            "tier": "Enterprise (Expired)",
            "is_licensed": True,
            "status": "EXPIRED",
            "status_label": f"License Expired on {expiry_date_str}",
            "is_valid": False,
            "organization": payload.get("organization", "Enterprise"),
            "license_id": payload.get("license_id", "N/A"),
            "max_users": max_users,
            "is_unlimited": is_unlimited,
            "current_users": current_user_count,
            "remaining_capacity": max(0, effective_max - current_user_count),
            "utilization_pct": min(100.0, utilization),
            "issued_date": payload.get("issued_date", "N/A"),
            "expiry_date": expiry_date_str,
            "is_perpetual": False,
            "days_remaining": 0,
            "can_create_user": can_create,
            "over_limit": current_user_count > effective_max,
            "notice": f"Your ZclockID Enterprise subscription expired on {expiry_date_str}. Please renew your license to manage more than 200 users."
        }

    # Valid Active License
    if is_unlimited:
        remaining = 999999
        utilization = 0.0
        can_create = True
    else:
        remaining = max(0, max_users - current_user_count)
        utilization = round((current_user_count / max_users) * 100, 1) if max_users > 0 else 0
        can_create = current_user_count < max_users

    return {
        "tier": payload.get("tier", "Enterprise Edition"),
        "is_licensed": True,
        "status": "ACTIVE",
        "status_label": "Active Enterprise License",
        "is_valid": True,
        "organization": payload.get("organization", "Enterprise Customer"),
        "license_id": payload.get("license_id", "N/A"),
        "max_users": max_users,
        "is_unlimited": is_unlimited,
        "current_users": current_user_count,
        "remaining_capacity": remaining,
        "utilization_pct": min(100.0, utilization),
        "issued_date": payload.get("issued_date", "N/A"),
        "expiry_date": "PERPETUAL" if is_perpetual else expiry_date_str,
        "is_perpetual": is_perpetual,
        "days_remaining": None if is_perpetual else days_remaining,
        "can_create_user": can_create,
        "over_limit": not is_unlimited and current_user_count > max_users,
        "features": payload.get("features", ["all"]),
        "author": "Atanu Majumdar (@atanumaj)",
        "author_url": "https://github.com/atanumaj",
        "copyright": "Copyright (c) 2026 Atanu Majumdar. All Rights Reserved.",
        "notice": "License active and in good standing."
    }

def install_license_file(license_content: str) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    """
    Validates and writes a new zclockid.lic file.
    Returns (success, license_info, error_message).
    """
    is_valid, payload, err = verify_license_text(license_content)
    if not is_valid or not payload:
        return False, {}, err or "License verification failed."

    target_path = PRIMARY_LICENSE_PATH
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(license_content.strip(), encoding="utf-8")
        target_path.chmod(0o644)
    except Exception as e:
        # Fallback to local /tmp or config dir if not running as root
        try:
            fb_path = Path("/tmp/zclockid.lic")
            fb_path.write_text(license_content.strip(), encoding="utf-8")
        except Exception as fb_err:
            return False, {}, f"Failed to save license to disk: {str(e)} (fallback: {str(fb_err)})"

    return True, payload, None

def remove_installed_license() -> bool:
    """Removes the installed license file to revert to Free Community Tier."""
    removed = False
    for p in [PRIMARY_LICENSE_PATH] + FALLBACK_LICENSE_PATHS:
        if p.exists():
            try:
                p.unlink()
                removed = True
            except Exception:
                pass
    return removed
