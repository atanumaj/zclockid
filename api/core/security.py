"""
ZclockID Enterprise Management Appliance - Security, Authentication & Cryptography
Handles PBKDF2-HMAC password hashing, session tokens, and Active Directory password complexity.
"""

import hashlib
import hmac
import os
import secrets
import re
from typing import Optional, Tuple
from pathlib import Path
from api.core.config import AD_CREDS_FILE, CONFIG_DIR

OTP_SECRET_FILE = CONFIG_DIR / "otp_secret"
_RUNTIME_OTP_KEY: Optional[bytes] = None


def get_otp_secret_key() -> bytes:
    """
    Retrieves or generates a persistent random 32-byte OTP HMAC key stored in CONFIG_DIR/otp_secret (mode 0600).
    No hardcoded fallback key is used.
    """
    global _RUNTIME_OTP_KEY
    env_secret = os.environ.get("ZCLOCKID_OTP_SECRET")
    if env_secret:
        return env_secret.strip().encode("utf-8")

    if OTP_SECRET_FILE.exists():
        try:
            key = OTP_SECRET_FILE.read_bytes().strip()
            if len(key) >= 32:
                return key
        except Exception:
            pass

    # Generate random 32-byte key and persist with 0600 permissions
    new_key = secrets.token_bytes(32)
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        fd = os.open(str(OTP_SECRET_FILE), flags, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(new_key)
        try:
            os.chmod(str(OTP_SECRET_FILE), 0o600)
        except Exception:
            pass
        return new_key
    except Exception:
        if _RUNTIME_OTP_KEY is None:
            _RUNTIME_OTP_KEY = secrets.token_bytes(32)
        return _RUNTIME_OTP_KEY


def hash_otp(otp_code: str) -> str:
    """Computes HMAC-SHA256 hex digest of an OTP code for secure at-rest storage."""
    key = get_otp_secret_key()
    return hmac.new(key, otp_code.strip().encode("utf-8"), hashlib.sha256).hexdigest()


def verify_otp_hash(provided_code: str, stored_hash: str) -> bool:
    """Validates an OTP code against stored HMAC-SHA256 hash using secrets.compare_digest."""
    if not provided_code or not stored_hash:
        return False
    computed = hash_otp(provided_code)
    return secrets.compare_digest(computed, stored_hash)

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return hashed, salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    check_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(check_hash, hashed)

def generate_session_token() -> str:
    return secrets.token_hex(32)

def generate_otp_code(length: int = 6) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(length))

def get_ad_creds() -> Tuple[str, str]:
    admin_user = "Administrator"
    admin_pass = ""
    if AD_CREDS_FILE.exists():
        try:
            with open(AD_CREDS_FILE) as f:
                for line in f:
                    if line.startswith("AD_ADMIN="):
                        admin_user = line.split("=", 1)[1].strip()
                    elif line.startswith("AD_PASS="):
                        admin_pass = line.split("=", 1)[1].strip()
        except Exception:
            pass
    return admin_user, admin_pass

def validate_ad_password_complexity(password: str, username: str = "", full_name: str = "") -> Tuple[bool, str]:
    """
    Validates password against standard Active Directory complexity policy:
    - Minimum length of 8 characters.
    - Contains characters from at least 3 of 4 categories:
      1. Uppercase English letters (A-Z)
      2. Lowercase English letters (a-z)
      3. Base 10 digits (0-9)
      4. Non-alphanumeric special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)
    - Does not contain user's sAMAccountName or parts of their full name.
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."

    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    categories = sum([has_upper, has_lower, has_digit, has_special])
    if categories < 3:
        return False, "Password must contain characters from at least 3 categories (Uppercase, Lowercase, Numbers, Symbols)."

    if username and len(username) >= 3 and username.lower() in password.lower():
        return False, "Password cannot contain your username."

    if full_name:
        for part in re.split(r'\s+', full_name.strip()):
            if len(part) >= 3 and part.lower() in password.lower():
                return False, f"Password cannot contain parts of your name ('{part}')."

    return True, "Password satisfies Active Directory complexity requirements."

