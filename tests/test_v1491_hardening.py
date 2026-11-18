"""
tests/test_v1491_hardening.py: Invariant and unit tests for v1.4.9.1.

Verifies:
1. get_samdb() fails closed in production: never returns MockSamDB unless ZCLOCKID_SAMDB_MOCK=1.
   Callers return 503 'Active Directory database unavailable'.
   Registration approval does NOT mark APPROVED or clear password_enc when provisioning fails.
2. LDAP filter escaping: escape every LDAP filter value with ldb.binary_encode().
   Wildcard username 'Administrato*' returns 404/400 and Administrator is untouched.
3. Privileged account modifications (password reset, disable, enable, never-expires toggle)
   blocked for operator role (403); allowed for fulladmin only.
4. temporary_auth_file created in root-only runtime directory (0700); stale files cleaned at startup.
"""

import os
import time
import sqlite3
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.main import app
from api.core.config import DB_PATH
from api.services.samdb_service import (
    get_samdb,
    SamDBUnavailableError,
    escape_ldap_filter_value,
    temporary_auth_file,
    cleanup_stale_auth_files,
    get_auth_runtime_dir,
    _global_mock_samdb
)
from api.routers.users import is_privileged_ad_user
import api.routers.registration as reg_mod
from api.routers.registration import (
    encrypt_registration_password,
    get_reg_db
)


@pytest.fixture(autouse=True)
def init_test_db(tmp_path, monkeypatch):
    """Initializes isolated database for test cases."""
    db_file = tmp_path / "test_v1491.db"
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            role TEXT DEFAULT 'readonly',
            last_active REAL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS self_registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            given_name TEXT,
            surname TEXT,
            email TEXT,
            mobile TEXT,
            department TEXT,
            password_hash TEXT,
            password_enc TEXT,
            status TEXT,
            created_at REAL,
            approved_at REAL,
            approved_by TEXT,
            notes TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS self_registration_settings (
            id INTEGER PRIMARY KEY,
            default_domain TEXT,
            default_group TEXT,
            default_bandwidth_profile_id INTEGER,
            require_admin_approval INTEGER DEFAULT 1
        )
    """)
    c.execute("""
        INSERT OR REPLACE INTO self_registration_settings (id, default_domain, default_group, default_bandwidth_profile_id, require_admin_approval)
        VALUES (1, 'corp.example.com', 'Domain Users', 0, 1)
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            action TEXT,
            actor TEXT,
            target TEXT,
            status TEXT,
            details TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS radius_bandwidth_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            download_mbps INTEGER,
            upload_mbps INTEGER,
            session_timeout_mins INTEGER,
            idle_timeout_mins INTEGER,
            daily_quota_mb INTEGER,
            ad_group TEXT,
            target_name TEXT,
            target_type TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS radius_user_bandwidth (
            username TEXT PRIMARY KEY,
            profile_id INTEGER,
            updated_at REAL
        )
    """)

    # Operator and fulladmin session tokens
    now_ts = time.time()
    c.execute(
        "INSERT INTO sessions (token, username, created_at, expires_at, role, last_active) VALUES (?, ?, ?, ?, ?, ?)",
        ("op_token_123", "operator_user", now_ts, now_ts + 3600, "operator", now_ts)
    )
    c.execute(
        "INSERT INTO sessions (token, username, created_at, expires_at, role, last_active) VALUES (?, ?, ?, ?, ?, ?)",
        ("admin_token_123", "admin_user", now_ts, now_ts + 3600, "fulladmin", now_ts)
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr("api.routers.auth.DB_PATH", db_file)
    monkeypatch.setattr("api.routers.users.DB_PATH", db_file)
    monkeypatch.setattr("api.routers.registration.DB_PATH", db_file)
    monkeypatch.setattr("api.core.config.DB_PATH", db_file)

    return db_file


# =============================================================================
# Requirement 1: Fail-Closed SamDB & Registration Approval Protection
# =============================================================================

def test_samdb_fails_closed_in_production(monkeypatch):
    """Never return MockSamDB in production when ZCLOCKID_SAMDB_MOCK is unset or 0."""
    monkeypatch.setenv("ZCLOCKID_SAMDB_MOCK", "0")
    monkeypatch.setattr("api.services.samdb_service.HAS_SAMBA_BINDINGS", False)

    with pytest.raises(SamDBUnavailableError) as exc_info:
        get_samdb()
    assert exc_info.value.status_code == 503
    assert "Active Directory database unavailable" in exc_info.value.detail


def test_registration_approval_does_not_approve_when_provisioning_fails(monkeypatch, init_test_db):
    """
    Registration approval must NOT mark APPROVED or clear password_enc
    when Active Directory provisioning fails (e.g. 503 SamDB unavailable).
    """
    client = TestClient(app, client=("127.0.0.1", 50000))

    # Insert a pending registration with encrypted password
    conn = sqlite3.connect(init_test_db)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO self_registrations (
            id, username, given_name, surname, email, mobile, department,
            password_enc, status, created_at
        ) VALUES (
            42, 'failuser', 'Fail', 'User', 'fail@example.com', '+1234567890', 'IT',
            'dummy_encrypted_payload', 'PENDING_APPROVAL', ?
        )
    """, (time.time(),))
    conn.commit()
    conn.close()

    # Mock decryption and provisioning failure
    monkeypatch.setattr(reg_mod, "decrypt_registration_password", lambda r_id, u, p: "DecryptedPass123!")
    
    def mock_failing_provision(*args, **kwargs):
        raise SamDBUnavailableError("Active Directory database unavailable")

    monkeypatch.setattr(reg_mod, "provision_user_in_ad", mock_failing_provision)

    # Call approve as admin
    resp = client.post(
        "/api/v1/registrations/requests/42/approve",
        json={"notes": "Approving"},
        headers={"Authorization": "Bearer admin_token_123"}
    )
    assert resp.status_code == 503, f"Expected 503, got {resp.status_code}: {resp.text}"

    # Verify database: must NOT be APPROVED, password_enc must NOT be cleared
    conn = sqlite3.connect(init_test_db)
    cursor = conn.cursor()
    cursor.execute("SELECT status, password_enc, approved_at FROM self_registrations WHERE id = 42")
    row = cursor.fetchone()
    conn.close()

    assert row[0] == "PENDING_APPROVAL", f"Status should remain PENDING_APPROVAL, got {row[0]}"
    assert row[1] == "dummy_encrypted_payload", f"password_enc must not be cleared, got {row[1]}"
    assert row[2] is None, "approved_at must remain None"


# =============================================================================
# Requirement 2: LDAP Filter Escaping & Wildcard Injection Protection
# =============================================================================

def test_ldap_filter_escaping_characters():
    """Verify escape_ldap_filter_value encodes RFC 4515 special characters."""
    assert escape_ldap_filter_value("Administrato*") in ("Administrato\\2a", "Administrato\\2A")
    assert escape_ldap_filter_value("foo(bar)") in ("foo\\28bar\\29", "foo\\28bar\\29")
    assert escape_ldap_filter_value("back\\slash") in ("back\\5cslash", "back\\5cslash")
    assert escape_ldap_filter_value("user\x00null") in ("user\\00null", "user\\00null")


def test_wildcard_username_does_not_touch_administrator():
    """
    Wildcard username 'Administrato*' must return 404/400 and leave Administrator untouched.
    """
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb
    db.users["Administrator"] = {
        "password": "RealAdminP@ss2026!",
        "enabled": True,
        "never_expires": True
    }

    # Attempt to reset password on 'Administrato*'
    resp = client.post(
        "/api/v1/users/Administrato*/password",
        json={"new_password": "HackedPassword123!"},
        headers={"Authorization": "Bearer admin_token_123"}
    )
    # Must fail with 400 or 404
    assert resp.status_code in (400, 404), f"Expected 400/404, got {resp.status_code}"

    # Verify Administrator password is completely unchanged!
    assert db.users["Administrator"]["password"] == "RealAdminP@ss2026!"


# =============================================================================
# Requirement 3: Privileged Account Modification Restrictions
# =============================================================================

def test_privileged_accounts_blocked_for_operator_allowed_for_fulladmin():
    """
    Block password reset, disable, enable, and never-expires toggle on privileged accounts
    (Administrator, krbtgt, Guest, Domain Admins members) for operator (403);
    allow fulladmin.
    """
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    # Setup privileged users in MockSamDB
    db.users["Administrator"] = {"password": "AdminOldPass123!", "enabled": True}
    db.users["krbtgt"] = {"password": "KrbtgtOldPass123!", "enabled": True}
    db.users["Guest"] = {"password": "GuestOldPass123!", "enabled": False}
    db.users["domadmin_user"] = {"password": "DomAdminOldPass123!", "enabled": True}
    db.groups["Domain Admins"] = {"members": {"domadmin_user"}}

    # Standard non-privileged user
    db.users["standard_user"] = {"password": "StdOldPass123!", "enabled": True}

    op_headers = {"Authorization": "Bearer op_token_123"}
    admin_headers = {"Authorization": "Bearer admin_token_123"}

    # 1. Operator attempts to reset password on Administrator -> 403
    r_op_pw = client.post("/api/v1/users/Administrator/password", json={"new_password": "NewSecretPass123!"}, headers=op_headers)
    assert r_op_pw.status_code == 403, f"Expected 403 for operator on Administrator password, got {r_op_pw.status_code}"

    # 2. Operator attempts to disable Administrator -> 403
    r_op_dis = client.post("/api/v1/users/Administrator/disable", headers=op_headers)
    assert r_op_dis.status_code == 403, f"Expected 403 for operator on Administrator disable, got {r_op_dis.status_code}"

    # 3. Operator attempts to enable Guest -> 403
    r_op_en = client.post("/api/v1/users/Guest/enable", headers=op_headers)
    assert r_op_en.status_code == 403, f"Expected 403 for operator on Guest enable, got {r_op_en.status_code}"

    # 4. Operator attempts never-expires toggle on krbtgt via PUT /users/{username} -> 403
    r_op_exp = client.put("/api/v1/users/krbtgt", json={"password_never_expires": True}, headers=op_headers)
    assert r_op_exp.status_code == 403, f"Expected 403 for operator on krbtgt expiry, got {r_op_exp.status_code}"

    # 5. Operator attempts password reset on Domain Admins member -> 403
    r_op_grp = client.post("/api/v1/users/domadmin_user/password", json={"new_password": "NewSecretPass123!"}, headers=op_headers)
    assert r_op_grp.status_code == 403, f"Expected 403 for operator on Domain Admins member, got {r_op_grp.status_code}"

    # 6. Operator operating on standard non-privileged user -> 200
    r_op_std = client.post("/api/v1/users/standard_user/password", json={"new_password": "NewSecretPass123!"}, headers=op_headers)
    assert r_op_std.status_code == 200, f"Expected 200 for operator on standard user, got {r_op_std.status_code}"

    # 7. Fulladmin operating on Administrator -> 200
    r_admin_pw = client.post("/api/v1/users/Administrator/password", json={"new_password": "NewSecretPass123!"}, headers=admin_headers)
    assert r_admin_pw.status_code == 200, f"Expected 200 for fulladmin on Administrator password, got {r_admin_pw.status_code}"


# =============================================================================
# Requirement 4: temporary_auth_file in Root-Only Directory & Startup Cleanup
# =============================================================================

def test_temporary_auth_file_location_and_permissions(tmp_path, monkeypatch):
    """Ensures temporary_auth_file is created in root-only runtime directory (0700) with 0600 mode."""
    test_auth_dir = tmp_path / "runtime_auth_test"
    monkeypatch.setenv("ZCLOCKID_AUTH_DIR", str(test_auth_dir))

    created_path = None
    with temporary_auth_file("testuser", "testpass") as auth_path:
        created_path = Path(auth_path)
        assert created_path.parent == test_auth_dir, f"Expected file in {test_auth_dir}, got {created_path.parent}"
        assert created_path.exists()
        # Verify file mode is 0600
        mode = created_path.stat().st_mode & 0o777
        assert mode == 0o600, f"Expected 0600 mode, got {oct(mode)}"

    # Automatically unlinked after context exit
    assert not created_path.exists()


def test_cleanup_stale_auth_files_at_startup(tmp_path, monkeypatch):
    """Ensures stale zclock_auth_* files are deleted upon startup."""
    test_auth_dir = tmp_path / "runtime_auth_cleanup"
    monkeypatch.setenv("ZCLOCKID_AUTH_DIR", str(test_auth_dir))

    test_auth_dir.mkdir(parents=True, exist_ok=True)
    stale1 = test_auth_dir / "zclock_auth_stale1.tmp"
    stale2 = test_auth_dir / "zclock_auth_stale2.tmp"
    other = test_auth_dir / "keep_other_file.txt"

    stale1.write_text("username=a\npassword=b\n")
    stale2.write_text("username=c\npassword=d\n")
    other.write_text("do not delete")

    deleted_count = cleanup_stale_auth_files()
    assert deleted_count == 2
    assert not stale1.exists()
    assert not stale2.exists()
    assert other.exists()
