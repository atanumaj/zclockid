"""
ZclockID SecretBox - AES-256-GCM Envelope Encryption for Self-Registration Passwords.
Keys are stored in CONFIG_DIR/registration_keys/<key_id> with mode 0600 (directory 0700).
Encrypted format: v1:<key_id>:<base64(nonce+ct)>
AAD: reg:{id}:{username}
"""

import os
import time
import base64
import secrets
from pathlib import Path
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from api.core.config import CONFIG_DIR, DB_PATH


class DecryptionError(Exception):
    """Raised when password decryption fails due to missing key, invalid format, or MAC mismatch."""
    pass


def get_registration_keys_dir() -> Path:
    """Returns registration keys directory, ensuring mode 0700."""
    key_dir = CONFIG_DIR / "registration_keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(key_dir), 0o700)
    except Exception:
        pass
    return key_dir


def create_new_key(key_id: Optional[str] = None) -> Tuple[str, bytes]:
    """
    Creates a new 32-byte AES-256 key in CONFIG_DIR/registration_keys/<key_id>
    with mode 0600 using os.O_CREAT | os.O_EXCL.
    """
    key_dir = get_registration_keys_dir()
    if not key_id:
        key_id = f"k_{int(time.time() * 1000)}_{secrets.token_hex(4)}"

    key_path = key_dir / key_id
    key_bytes = os.urandom(32)

    fd = os.open(str(key_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, key_bytes)
    finally:
        os.close(fd)

    try:
        os.chmod(str(key_path), 0o600)
    except Exception:
        pass

    return key_id, key_bytes


def get_key_by_id(key_id: str) -> Optional[bytes]:
    """Retrieves an encryption key by key_id. Never falls back to a hardcoded key."""
    if not key_id or "/" in key_id or "\\" in key_id or key_id.startswith("."):
        return None
    key_path = get_registration_keys_dir() / key_id
    if not key_path.is_file():
        return None
    try:
        with open(key_path, "rb") as f:
            data = f.read()
            if len(data) == 32:
                return data
    except Exception:
        pass
    return None


def get_newest_key() -> Tuple[str, bytes]:
    """
    Finds the newest key in CONFIG_DIR/registration_keys (by mtime/name).
    If no keys exist, generates one.
    """
    key_dir = get_registration_keys_dir()
    valid_keys = []
    for item in key_dir.iterdir():
        if item.is_file() and not item.name.startswith("."):
            try:
                st = item.stat()
                if st.st_size == 32:
                    valid_keys.append((st.st_mtime_ns, item.name, item))
            except Exception:
                pass

    if not valid_keys:
        return create_new_key()

    # Sort by mtime_ns ascending, then filename ascending -> newest is last
    valid_keys.sort(key=lambda x: (x[0], x[1]))
    newest = valid_keys[-1]
    with open(newest[2], "rb") as f:
        return newest[1], f.read()


def encrypt_registration_password(reg_id: int, username: str, plaintext: str) -> str:
    """
    Encrypts chosen password using AES-256-GCM.
    Format: v1:<key_id>:<base64(nonce+ct)>
    AAD: reg:{id}:{username}
    """
    key_id, key_bytes = get_newest_key()
    nonce = os.urandom(12)
    aad = f"reg:{reg_id}:{username}".encode("utf-8")

    aesgcm = AESGCM(key_bytes)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

    payload = base64.b64encode(nonce + ct).decode("ascii")
    return f"v1:{key_id}:{payload}"


def decrypt_registration_password(reg_id: int, username: str, enc_str: str) -> str:
    """
    Decrypts registration password.
    Format: v1:<key_id>:<base64(nonce+ct)>
    AAD: reg:{id}:{username}
    Raises DecryptionError on any failure.
    """
    if not enc_str or not isinstance(enc_str, str) or not enc_str.startswith("v1:"):
        raise DecryptionError("Invalid encrypted password format (must start with v1:)")

    parts = enc_str.split(":", 2)
    if len(parts) != 3 or parts[0] != "v1":
        raise DecryptionError("Malformed encrypted password string")

    key_id = parts[1]
    payload_b64 = parts[2]

    key_bytes = get_key_by_id(key_id)
    if not key_bytes:
        raise DecryptionError(f"Encryption key '{key_id}' not found in registration_keys")

    try:
        raw = base64.b64decode(payload_b64)
    except Exception as e:
        raise DecryptionError(f"Base64 decode failed: {e}")

    if len(raw) < 28:  # 12-byte nonce + 16-byte tag minimum
        raise DecryptionError("Ciphertext payload too short")

    nonce = raw[:12]
    ct = raw[12:]
    aad = f"reg:{reg_id}:{username}".encode("utf-8")

    try:
        aesgcm = AESGCM(key_bytes)
        pt = aesgcm.decrypt(nonce, ct, aad)
        return pt.decode("utf-8")
    except Exception as e:
        raise DecryptionError(f"AES-GCM authentication/decryption failed: {e}")


def check_missing_registration_keys() -> int:
    """Returns the count of active pending registrations referencing missing encryption keys."""
    try:
        import sqlite3
        if not DB_PATH.exists():
            return 0
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password_enc FROM self_registrations WHERE status IN ('PENDING_OTP', 'PENDING_APPROVAL') AND password_enc IS NOT NULL")
        rows = cursor.fetchall()
        conn.close()

        key_dir = get_registration_keys_dir()
        missing = 0
        for (enc_str,) in rows:
            if enc_str and enc_str.startswith("v1:"):
                parts = enc_str.split(":", 2)
                if len(parts) >= 2:
                    k_id = parts[1]
                    if not (key_dir / k_id).is_file():
                        missing += 1
        return missing
    except Exception:
        return 0
