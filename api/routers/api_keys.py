"""
ZclockID API Key Management Router
Manages secure programmatic API tokens (zck_live_...) with granular scopes, CIDR restrictions, and revocation.
"""

import time
import json
import secrets
import hashlib
import sqlite3
import ipaddress
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Header, Request, status, Depends

from api.core.config import DB_PATH
from api.services.system_service import log_audit
from api.routers.auth import require_role
from api.schemas.api_key_schema import (
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyItemResponse,
    VALID_SCOPES
)

router = APIRouter(prefix="/api/v1/api-keys", tags=["API Key Management"], dependencies=[Depends(require_role("readonly"))])

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_key(raw_token: str) -> str:
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()

def is_ip_in_cidr(client_ip: str, cidr_whitelist: str) -> bool:
    """Verifies if client_ip matches one of the comma-separated CIDR blocks."""
    if not cidr_whitelist or cidr_whitelist.strip() in ["*", "0.0.0.0/0", "::/0"]:
        return True
    try:
        c_ip = ipaddress.ip_address(client_ip)
        for block in cidr_whitelist.split(","):
            block = block.strip()
            if not block:
                continue
            if "/" not in block:
                block = f"{block}/32"
            if c_ip in ipaddress.ip_network(block, strict=False):
                return True
        return False
    except Exception:
        return False

@router.get("", response_model=List[ApiKeyItemResponse])
def list_api_keys():
    """Lists all configured API keys (tokens are redacted, only prefixes are shown)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, name, key_prefix, scopes, cidr_whitelist, expires_at, last_used_at, is_active, created_at
        FROM api_keys
        ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        try:
            scopes_list = json.loads(r["scopes"])
        except Exception:
            scopes_list = [s.strip() for s in r["scopes"].split(",") if s.strip()]
        result.append(ApiKeyItemResponse(
            id=r["id"],
            name=r["name"],
            key_prefix=r["key_prefix"],
            scopes=scopes_list,
            cidr_whitelist=r["cidr_whitelist"] or "0.0.0.0/0",
            expires_at=r["expires_at"],
            last_used_at=r["last_used_at"],
            is_active=bool(r["is_active"]),
            created_at=r["created_at"]
        ))
    return result

@router.post("", response_model=ApiKeyCreateResponse, status_code=status.HTTP_201_CREATED)
def create_api_key(req: ApiKeyCreateRequest, request: Request):
    """
    Generates a new API token with specified scopes and IP CIDR restrictions.
    The raw token is returned once upon generation and cannot be recovered later.
    """
    # 1. Validate scopes
    for s in req.scopes:
        if s not in VALID_SCOPES:
            raise HTTPException(status_code=400, detail=f"Invalid scope '{s}'. Allowed: {', '.join(VALID_SCOPES)}")

    if not req.scopes:
        raise HTTPException(status_code=400, detail="At least one scope must be selected.")

    # 2. Validate CIDR format
    cidr_val = req.cidr_whitelist.strip() if req.cidr_whitelist else "0.0.0.0/0"
    for block in cidr_val.split(","):
        block = block.strip()
        if block in ["*", "0.0.0.0/0", "::/0"]:
            continue
        try:
            if "/" not in block:
                block = f"{block}/32"
            ipaddress.ip_network(block, strict=False)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid CIDR notation '{block}': {str(e)}")

    # 3. Generate token
    token_entropy = secrets.token_hex(20)
    full_token = f"zck_live_{token_entropy}"
    prefix = f"zck_live_{token_entropy[:6]}..."
    hashed = hash_key(full_token)

    now = time.time()
    expires_at = None
    if req.expires_days and req.expires_days > 0:
        expires_at = now + (req.expires_days * 86400)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO api_keys (name, key_prefix, key_hash, scopes, cidr_whitelist, expires_at, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    """, (req.name.strip(), prefix, hashed, json.dumps(req.scopes), cidr_val, expires_at, now))
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_audit("API_KEY_CREATED", "admin", f"key:{new_id}:{req.name}", "SUCCESS", {
        "scopes": req.scopes,
        "cidr": cidr_val,
        "expires_at": expires_at
    })

    return ApiKeyCreateResponse(
        id=new_id,
        name=req.name.strip(),
        key_prefix=prefix,
        full_api_key=full_token,
        scopes=req.scopes,
        cidr_whitelist=cidr_val,
        expires_at=expires_at,
        created_at=now
    )

@router.delete("/{key_id}")
def revoke_api_key(key_id: int):
    """Permanently revokes an API key."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name, key_prefix FROM api_keys WHERE id = ?", (key_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="API key not found.")

    cursor.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()

    log_audit("API_KEY_REVOKED", "admin", f"key:{key_id}:{row['name']}", "SUCCESS", {"prefix": row["key_prefix"]})
    return {"status": "success", "message": f"API key '{row['name']}' permanently revoked."}

def validate_token_header(raw_token: str, client_ip: str, required_scope: Optional[str] = None) -> bool:
    """Internal validator for API key requests."""
    hashed = hash_key(raw_token)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, scopes, cidr_whitelist, expires_at, is_active
        FROM api_keys
        WHERE key_hash = ?
    """, (hashed,))
    row = cursor.fetchone()

    if not row or not row["is_active"]:
        conn.close()
        return False

    if row["expires_at"] and row["expires_at"] < time.time():
        conn.close()
        return False

    if not is_ip_in_cidr(client_ip, row["cidr_whitelist"]):
        conn.close()
        return False

    if required_scope:
        try:
            scopes = json.loads(row["scopes"])
        except Exception:
            scopes = [s.strip() for s in row["scopes"].split(",")]
        if "admin:all" not in scopes and required_scope not in scopes:
            conn.close()
            return False

    # Update last_used_at timestamp
    cursor.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (time.time(), row["id"]))
    conn.commit()
    conn.close()
    return True

