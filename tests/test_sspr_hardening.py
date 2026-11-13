"""
ZclockID SSPR & Self-Registration Hardening Test Suite (v1.3.5)
==============================================================
Validates security hardening for Self-Service Password Reset and Self-Registration:
1. No otp_debug in any response and 503 when no channel is configured.
2. Request lock after 5 wrong OTP codes (status = LOCKED).
3. Privileged accounts (Administrator, krbtgt, Guest, adminCount=1, Domain Admins) refused.
4. LDAP RFC 4515 escaping and rejection of '*', ')(', and leading '-' usernames.
5. Identical generic responses for existing and nonexistent users on request-otp.
6. Absence of otp_code / plaintext OTP in admin logs and CSV export.
"""

import os
import re
import time
import tempfile
import sqlite3
from pathlib import Path

try:
    import pytest
except ImportError:
    pytest = None

from fastapi.testclient import TestClient

from api.main import app
from api.db.init_db import init_db
import api.core.config as config
import api.routers.auth as auth_mod
import api.routers.self_service as ss_mod
import api.routers.registration as reg_mod
import api.services.security_service as sec_svc
from api.core.security import hash_otp, verify_otp_hash


if pytest is not None:
    @pytest.fixture(autouse=True)
    def allow_testclient_in_tests(monkeypatch):
        """Allows testclient / 127.0.0.1 in the security baseline firewall check during tests."""
        orig_is_ip_allowed = sec_svc.is_ip_allowed
        monkeypatch.setattr(
            sec_svc,
            "is_ip_allowed",
            lambda ip, allowed: True if ip in ("testclient", "127.0.0.1") else orig_is_ip_allowed(ip, allowed)
        )


def _setup_test_environment(tmp_path: Path):
    """Sets up a clean temporary SQLite database with schema for tests."""
    db_file = tmp_path / "test_zclockid.db"
    orig_db_path = config.DB_PATH
    orig_ss_db = ss_mod.DB_PATH
    orig_reg_db = reg_mod.DB_PATH
    orig_auth_db = auth_mod.DB_PATH

    import api.db.init_db as init_db_mod
    orig_init_db = getattr(init_db_mod, "DB_PATH", None)
    init_db_mod.DB_PATH = db_file

    import api.services.log_retention_service as lrs
    orig_lrs_db = getattr(lrs, "DB_PATH", None)
    lrs.DB_PATH = db_file

    config.DB_PATH = db_file
    ss_mod.DB_PATH = db_file
    reg_mod.DB_PATH = db_file
    auth_mod.DB_PATH = db_file

    init_db_mod.init_db(db_file)

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Create admin session for authenticated log queries
    now = time.time()
    admin_token = "sspr_test_admin_token"
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE,
            username TEXT,
            created_at REAL,
            expires_at REAL,
            role TEXT,
            last_active REAL
        )
    """)
    cursor.execute(
        "INSERT INTO sessions (token, username, created_at, expires_at, role, last_active) VALUES (?, 'admin', ?, ?, 'fulladmin', ?)",
        (admin_token, now, now + 3600, now)
    )
    conn.commit()
    conn.close()

    return db_file, admin_token, (orig_db_path, orig_ss_db, orig_reg_db, orig_auth_db, orig_init_db, orig_lrs_db)


def _restore_environment(orig_paths):
    import api.db.init_db as init_db_mod
    import api.services.log_retention_service as lrs
    config.DB_PATH, ss_mod.DB_PATH, reg_mod.DB_PATH, auth_mod.DB_PATH, init_db_orig, lrs_orig = orig_paths
    if init_db_orig is not None:
        init_db_mod.DB_PATH = init_db_orig
    if lrs_orig is not None:
        lrs.DB_PATH = lrs_orig


def test_no_otp_debug_in_any_response():
    """Verifies that otp_debug is never present in any SSPR or registration response, and 503 if unconfigured."""
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

            # 1. By default, SMTP and real SMS are unconfigured -> request-otp must return 503
            res_otp = client.post("/api/v1/self-service/password/request-otp", json={
                "username": "jdoe",
                "channel": "email"
            })
            assert res_otp.status_code == 503, f"Expected 503 when SMTP unconfigured, got {res_otp.status_code}"
            assert "otp_debug" not in res_otp.text

            res_sms = client.post("/api/v1/self-service/password/request-otp", json={
                "username": "jdoe",
                "channel": "sms"
            })
            assert res_sms.status_code == 503, f"Expected 503 when SMS unconfigured, got {res_sms.status_code}"
            assert "otp_debug" not in res_sms.text

            # 2. Registration initiate with unconfigured SMS gateway -> 503
            res_reg = client.post("/api/v1/public/register/initiate", json={
                "username": "newuser",
                "password": "Password123!",
                "given_name": "New",
                "surname": "User",
                "email": "new@example.com",
                "mobile": "+1234567890"
            })
            assert res_reg.status_code == 503, f"Expected 503 for registration with unconfigured SMS, got {res_reg.status_code}"
            assert "otp_debug" not in res_reg.text

            # 3. Configure SMTP in SSPR settings and test successful request-otp response has no otp_debug
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("UPDATE self_service_password_settings SET email_smtp_enabled = 1, smtp_host = 'smtp.test.local' WHERE id = 1")
            conn.commit()
            conn.close()

            # Mock lookup_ad_user to return valid user
            orig_lookup = ss_mod.lookup_ad_user
            orig_dispatch = ss_mod.dispatch_email
            ss_mod.lookup_ad_user = lambda u: {
                "found": True,
                "username": "jdoe",
                "email": "jdoe@example.com",
                "mobile": None,
                "is_disabled": False,
                "is_privileged": False
            }
            ss_mod.dispatch_email = lambda *args, **kwargs: (True, "sent")

            try:
                res_ok = client.post("/api/v1/self-service/password/request-otp", json={
                    "username": "jdoe",
                    "channel": "email"
                })
                assert res_ok.status_code == 200, f"Expected 200, got {res_ok.status_code}: {res_ok.text}"
                data = res_ok.json()
                assert "otp_debug" not in data, "Security vulnerability: otp_debug found in response!"
                assert "otp" not in data
                assert "otp_code" not in data
            finally:
                ss_mod.lookup_ad_user = orig_lookup
                ss_mod.dispatch_email = orig_dispatch

        finally:
            _restore_environment(orig)


def test_lock_after_5_wrong_codes():
    """Verifies that an OTP request is marked LOCKED after 5 consecutive incorrect guesses."""
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

            # Allow 10 daily attempts so we can test the 5-guess lock without triggering 429 daily rate limit
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("UPDATE self_service_password_settings SET max_daily_attempts = 10 WHERE id = 1")

            # Insert an active reset request with hashed OTP '123456'
            real_otp = "123456"
            hashed = hash_otp(real_otp)
            cursor.execute("""
                INSERT INTO self_service_password_logs (
                    username, method, recipient, otp_code, otp_expires_at, status,
                    ip_address, user_agent, created_at, failed_attempts
                ) VALUES ('victim_user', 'EMAIL_OTP', 'registered email', ?, ?, 'PENDING_OTP', '127.0.0.1', 'pytest', ?, 0)
            """, (hashed, time.time() + 600, time.time()))
            reset_id = cursor.lastrowid
            conn.commit()
            conn.close()

            # Attempt 4 wrong codes: should return 400 with remaining attempts
            for i in range(1, 5):
                res = client.post("/api/v1/self-service/password/verify-and-reset", json={
                    "username": "victim_user",
                    "reset_id": reset_id,
                    "otp_code": f"00000{i}",
                    "new_password": "ValidNewPassword123!"
                })
                assert res.status_code == 400
                assert "attempts remaining" in res.json().get("detail", "").lower()

            # 5th wrong code: must lock the request
            res_5 = client.post("/api/v1/self-service/password/verify-and-reset", json={
                "username": "victim_user",
                "reset_id": reset_id,
                "otp_code": "999999",
                "new_password": "ValidNewPassword123!"
            })
            assert res_5.status_code == 400
            assert "locked" in res_5.json().get("detail", "").lower()

            # 6th attempt (even with CORRECT code): must refuse because status is LOCKED
            res_locked = client.post("/api/v1/self-service/password/verify-and-reset", json={
                "username": "victim_user",
                "reset_id": reset_id,
                "otp_code": real_otp,
                "new_password": "ValidNewPassword123!"
            })
            assert res_locked.status_code == 400
            assert "locked" in res_locked.json().get("detail", "").lower()

            # Verify database record state
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT status, failed_attempts FROM self_service_password_logs WHERE id = ?", (reset_id,))
            row = cursor.fetchone()
            conn.close()

            assert row[0] == "LOCKED", f"Expected status 'LOCKED', got '{row[0]}'"
            assert row[1] == 5, f"Expected 5 failed attempts, got {row[1]}"

        finally:
            _restore_environment(orig)


def test_sspr_daily_rate_limiting_returns_429():
    """Verifies that exceeding max_daily_attempts returns HTTP 429 Too Many Requests."""
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

            # Set max_daily_attempts to 3
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("UPDATE self_service_password_settings SET max_daily_attempts = 3, email_smtp_enabled = 1, smtp_host = 'smtp.test.local' WHERE id = 1")
            conn.commit()
            conn.close()

            orig_lookup = ss_mod.lookup_ad_user
            orig_dispatch = ss_mod.dispatch_email
            ss_mod.lookup_ad_user = lambda u: {"found": True, "username": "limit_user", "email": "limit@test.local", "mobile": None, "is_disabled": False, "is_privileged": False}
            ss_mod.dispatch_email = lambda *args, **kwargs: (True, "sent")

            try:
                for _ in range(3):
                    r = client.post("/api/v1/self-service/password/request-otp", json={"username": "limit_user", "channel": "email"})
                    assert r.status_code == 200

                # 4th attempt: must return 429 Too Many Requests
                r_blocked = client.post("/api/v1/self-service/password/request-otp", json={"username": "limit_user", "channel": "email"})
                assert r_blocked.status_code == 429
                assert "rate limit exceeded" in r_blocked.json().get("detail", "").lower()
            finally:
                ss_mod.lookup_ad_user = orig_lookup
                ss_mod.dispatch_email = orig_dispatch

        finally:
            _restore_environment(orig)


def test_administrator_and_privileged_accounts_refused():
    """Verifies that Administrator, krbtgt, Guest, adminCount=1, and Domain Admins are blocked from SSPR."""
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

            # 1. Unit check of helper is_privileged_account
            assert ss_mod.is_privileged_account("Administrator") is True
            assert ss_mod.is_privileged_account("administrator") is True
            assert ss_mod.is_privileged_account("krbtgt") is True
            assert ss_mod.is_privileged_account("Guest") is True
            assert ss_mod.is_privileged_account("regular_user", admin_count=1) is True
            assert ss_mod.is_privileged_account("regular_user", admin_count=0, member_of=["CN=Domain Admins,CN=Users,DC=corp"]) is True
            assert ss_mod.is_privileged_account("regular_user", admin_count=0, member_of=["CN=Enterprise Admins,CN=Users,DC=corp"]) is True
            assert ss_mod.is_privileged_account("regular_user", admin_count=0, member_of=["CN=Schema Admins,CN=Users,DC=corp"]) is True
            assert ss_mod.is_privileged_account("regular_user", admin_count=0, member_of=["CN=Administrators,CN=Builtin,DC=corp"]) is True
            assert ss_mod.is_privileged_account("standard_user", admin_count=0, member_of=["CN=Domain Users,CN=Users,DC=corp"]) is False

            # 2. change-with-old refuses Administrator with 403
            res_admin_change = client.post("/api/v1/self-service/password/change-with-old", json={
                "username": "Administrator",
                "old_password": "AnyOldPassword123!",
                "new_password": "NewValidPassword123!"
            })
            assert res_admin_change.status_code == 403, f"Expected 403 for Administrator, got {res_admin_change.status_code}"
            assert "privileged" in res_admin_change.json().get("detail", "").lower()

            # 3. verify-and-reset refuses Administrator with 403
            res_admin_reset = client.post("/api/v1/self-service/password/verify-and-reset", json={
                "username": "Administrator",
                "reset_id": 9999,
                "otp_code": "123456",
                "new_password": "NewValidPassword123!"
            })
            assert res_admin_reset.status_code == 403, f"Expected 403 for Administrator verify-and-reset, got {res_admin_reset.status_code}"

        finally:
            _restore_environment(orig)


def test_rfc4515_escaping_and_special_character_rejection():
    """Verifies that * and )( are rejected and that rfc4515_escape properly sanitizes LDAP filter values."""
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

            # 1. Test rfc4515_escape function
            assert ss_mod.rfc4515_escape("admin*user") == "admin\\2auser"
            assert ss_mod.rfc4515_escape("admin)(user") == "admin\\29\\28user"
            assert ss_mod.rfc4515_escape("test\\slash") == "test\\5cslash"
            assert ss_mod.rfc4515_escape("nul\x00byte") == "nul\\00byte"

            # 2. Rejection of invalid username inputs
            invalid_usernames = [
                "*",
                "user*",
                "*)(objectClass=*",
                "-leadingdash",
                "user name with spaces",
                "user;injection",
                "user'quote"
            ]

            for bad_user in invalid_usernames:
                # request-otp must reject with 400
                res_req = client.post("/api/v1/self-service/password/request-otp", json={
                    "username": bad_user,
                    "channel": "email"
                })
                # Even if 503 is checked, channel is checked after username format in request-otp or 400
                assert res_req.status_code == 400, f"Expected 400 for '{bad_user}', got {res_req.status_code}"

                # change-with-old must reject with 400
                res_old = client.post("/api/v1/self-service/password/change-with-old", json={
                    "username": bad_user,
                    "old_password": "Password123!",
                    "new_password": "Password123!"
                })
                assert res_old.status_code == 400, f"Expected 400 for '{bad_user}' in change-with-old, got {res_old.status_code}"

        finally:
            _restore_environment(orig)


def test_identical_responses_for_existing_and_nonexistent_users():
    """Verifies that request-otp returns identical status, recipient_masked, and message for existing and nonexistent users."""
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

            # Configure SMTP so channel check passes
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("UPDATE self_service_password_settings SET email_smtp_enabled = 1, smtp_host = 'smtp.test.local' WHERE id = 1")
            conn.commit()
            conn.close()

            orig_lookup = ss_mod.lookup_ad_user
            orig_dispatch = ss_mod.dispatch_email
            ss_mod.dispatch_email = lambda *args, **kwargs: (True, "sent")

            # Mock lookup: 'alice' exists; 'bob_nonexistent' does not
            def mock_lookup(username):
                if username == "alice":
                    return {
                        "found": True,
                        "username": "alice",
                        "email": "alice@example.com",
                        "mobile": None,
                        "is_disabled": False,
                        "is_privileged": False
                    }
                return {"found": False}

            ss_mod.lookup_ad_user = mock_lookup

            try:
                res_exist = client.post("/api/v1/self-service/password/request-otp", json={
                    "username": "alice",
                    "channel": "email"
                })
                res_nonexist = client.post("/api/v1/self-service/password/request-otp", json={
                    "username": "bob_nonexistent",
                    "channel": "email"
                })

                assert res_exist.status_code == 200, f"Existing user failed: {res_exist.status_code}"
                assert res_nonexist.status_code == 200, f"Nonexistent user failed: {res_nonexist.status_code}"

                data_exist = res_exist.json()
                data_nonexist = res_nonexist.json()

                # Compare anti-enumeration parity
                assert data_exist["status"] == data_nonexist["status"] == "otp_sent"
                assert data_exist["channel"] == data_nonexist["channel"] == "email"
                assert data_exist["message"] == data_nonexist["message"]
                assert data_exist["recipient_masked"] == data_nonexist["recipient_masked"] == "registered email"

                # Ensure reset_id is present in both without disclosing existence
                assert isinstance(data_exist["reset_id"], int)
                assert isinstance(data_nonexist["reset_id"], int)

            finally:
                ss_mod.lookup_ad_user = orig_lookup
                ss_mod.dispatch_email = orig_dispatch

        finally:
            _restore_environment(orig)


def test_no_otp_field_in_logs_endpoint():
    """Verifies that the admin logs and CSV export endpoints never return otp_code or hashed OTPs."""
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, admin_token, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

            # Insert sample log rows with sensitive OTP hash
            secret_hash = hash_otp("654321")
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO self_service_password_logs (
                    username, method, recipient, otp_code, otp_expires_at, status,
                    ip_address, user_agent, created_at, completed_at, notes, failed_attempts
                ) VALUES ('loguser', 'EMAIL_OTP', 'loguser@example.com', ?, ?, 'COMPLETED', '127.0.0.1', 'pytest', ?, ?, 'Done', 0)
            """, (secret_hash, time.time() + 600, time.time(), time.time()))
            conn.commit()
            conn.close()

            # 1. Query JSON logs endpoint with admin session token
            headers = {"Authorization": f"Bearer {admin_token}"}
            res_logs = client.get("/api/v1/self-service/password/logs", headers=headers)
            assert res_logs.status_code == 200, f"Logs endpoint returned {res_logs.status_code}"
            logs_data = res_logs.json().get("logs", [])
            assert len(logs_data) > 0, "No log records returned"

            for entry in logs_data:
                assert "otp_code" not in entry, f"Security violation: otp_code leaked in logs endpoint: {entry}"
                assert "otp" not in entry
                assert secret_hash not in str(entry)

            # 2. Query CSV export endpoint
            res_csv = client.get("/api/v1/self-service/password/logs/export", headers=headers)
            assert res_csv.status_code == 200, f"CSV export returned {res_csv.status_code}"
            csv_text = res_csv.text
            assert "otp_code" not in csv_text.lower()
            assert secret_hash not in csv_text

        finally:
            _restore_environment(orig)


if __name__ == "__main__":
    orig_is_ip_allowed = sec_svc.is_ip_allowed
    sec_svc.is_ip_allowed = lambda ip, allowed: True if ip in ("testclient", "127.0.0.1") else orig_is_ip_allowed(ip, allowed)

    print("Running test_no_otp_debug_in_any_response...")
    test_no_otp_debug_in_any_response()
    print("Running test_lock_after_5_wrong_codes...")
    test_lock_after_5_wrong_codes()
    print("Running test_administrator_and_privileged_accounts_refused...")
    test_administrator_and_privileged_accounts_refused()
    print("Running test_rfc4515_escaping_and_special_character_rejection...")
    test_rfc4515_escaping_and_special_character_rejection()
    print("Running test_identical_responses_for_existing_and_nonexistent_users...")
    test_identical_responses_for_existing_and_nonexistent_users()
    print("Running test_no_otp_field_in_logs_endpoint...")
    test_no_otp_field_in_logs_endpoint()
    print("ALL SSPR HARDENING TESTS PASSED SUCCESSFULLY!")
