"""
api/core/snmp_security.py: Security validation and atomic file operations for SNMP.
Prevents configuration injection attacks into snmpd.conf.
"""

import re
import os
import time
import ipaddress
from pathlib import Path
from typing import List, Optional
from fastapi import HTTPException, status

# Community string: alphanumeric plus . _ -, between 8 and 64 characters
COMMUNITY_REGEX = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

# Safe user/identifier: alphanumeric plus . _ -, between 1 and 64 characters
SAFE_IDENTIFIER_REGEX = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def validate_snmp_community(community: str) -> str:
    """
    Validates SNMP community string.
    Must match ^[A-Za-z0-9._-]{8,64}$ and contain no newlines, spaces, or '#'.
    """
    if not community or not isinstance(community, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Community string is required and must be 8-64 characters."
        )

    # Check for forbidden characters
    if any(c in community for c in ("\n", "\r", " ", "#")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Community string must not contain newlines, spaces, or '#' characters."
        )

    if not COMMUNITY_REGEX.match(community):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Community string must match ^[A-Za-z0-9._-]{8,64}$ (8 to 64 alphanumeric characters, dots, underscores, or hyphens)."
        )

    return community


def validate_snmp_source(source: str) -> str:
    """
    Validates an SNMP source host or network.
    Must be a valid IPv4 or IPv6 IP address or CIDR network.
    Rejects newlines, spaces, and '#'.
    """
    if not source or not isinstance(source, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SNMP source subnet or IP is required."
        )

    clean_source = source.strip()
    if any(c in clean_source for c in ("\n", "\r", " ", "#")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SNMP source '{clean_source}' must not contain newlines, spaces, or '#' characters."
        )

    try:
        # Validate using ipaddress.ip_network
        net = ipaddress.ip_network(clean_source, strict=False)
        return str(net)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid SNMP source '{clean_source}'. Must be a valid IPv4 or IPv6 address or CIDR."
        )


def validate_snmp_subnets(subnets_str: str) -> List[str]:
    """
    Validates a comma-separated list of SNMP allowed subnets/sources.
    """
    if not subnets_str or not isinstance(subnets_str, str):
        return ["127.0.0.1/32"]

    tokens = [t.strip() for t in subnets_str.split(",") if t.strip()]
    if not tokens:
        return ["127.0.0.1/32"]

    validated = []
    for token in tokens:
        val = validate_snmp_source(token)
        validated.append(val)
    return validated


def validate_snmp_text_field(value: Optional[str], field_name: str, max_length: int = 128) -> str:
    """
    Validates sysLocation, sysContact, agentAddress, or other text fields.
    Rejects newlines, carriage returns, and '#'.
    """
    val = (value or "").strip()
    if not val:
        return ""

    if any(c in val for c in ("\n", "\r", "#")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Field '{field_name}' must not contain newlines or '#' characters."
        )

    if len(val) > max_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Field '{field_name}' exceeds maximum length of {max_length} characters."
        )

    return val


def validate_snmpv3_user(username: Optional[str]) -> Optional[str]:
    """
    Validates an SNMPv3 USM username.
    Rejects newlines, spaces, and '#'.
    """
    if not username:
        return None
    u = username.strip()
    if any(c in u for c in ("\n", "\r", " ", "#")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SNMPv3 username must not contain newlines, spaces, or '#' characters."
        )
    if not SAFE_IDENTIFIER_REGEX.match(u):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SNMPv3 username must be alphanumeric (1-64 chars) with only . _ - permitted."
        )
    return u


def validate_snmpv3_password(password: Optional[str], field_name: str = "snmpv3_password") -> Optional[str]:
    """
    Validates SNMPv3 authentication or privacy passphrase.
    Rejects newlines, spaces, and '#'.
    """
    if not password:
        return None
    if any(c in password for c in ("\n", "\r", " ", "#")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must not contain newlines, spaces, or '#' characters."
        )
    if len(password) < 8 or len(password) > 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between 8 and 64 characters."
        )
    return password


def write_snmp_config_atomic(conf_path: Path, content: str, mode: int = 0o600) -> None:
    """
    Writes configuration atomically to conf_path with mode 0600.
    Ensures non-root users cannot read or inject content during write.
    """
    conf_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = conf_path.with_name(f"{conf_path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
        fd = os.open(str(tmp_path), flags, mode)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(content)
        try:
            os.chmod(str(tmp_path), mode)
        except Exception:
            pass
        os.replace(str(tmp_path), str(conf_path))
        try:
            os.chmod(str(conf_path), mode)
        except Exception:
            pass
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
