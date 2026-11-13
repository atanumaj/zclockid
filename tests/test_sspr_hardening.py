"""
ZclockID SSPR & Self-Registration Hardening Test Suite (v1.3.6)
==============================================================
Validates security hardening for Self-Service Password Reset and Self-Registration:
1. No otp_debug in any response and 503 when no channel is configured.
2. Request lock after 5 wrong OTP codes (status = LOCKED).
3. Privileged accounts (Administrator, krbtgt, Guest, adminCount=1, Domain Admins) refused.
4. LDAP RFC 4515 escaping and rejection of '*', ')(', and leading '-' usernames.
5. Identical generic responses for existing and nonexistent users on request-otp.
6. Absence of otp_code / plaintext OTP in admin logs and CSV export.
7. Verify accepts email, UPN, and case-insensitive username via reset_id.
8. Indistinguishable fake request behavior for ineligible/nonexistent accounts.
9. Nested admin-group detection via LDAP filter matching rule in chain (1.2.840.113556.1.4.1941).
10. OTP secret key generation (32 bytes, mode 0600) without hardcoded fallback.
11. Configurable max_daily_attempts_per_ip (50) and per-user (5) rate limits.
12. Registration failed_attempts carry-over on resubmit and 3 SMS/hr rate limiting.
13. Public /password/config reporting only actually configured channels.
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

            # 3. verify-and-reset with wrong code returns 400 (no early privilege leak)
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            real_admin_otp = "123456"
            admin_otp_hash = hash_otp(real_admin_otp)
            cursor.execute("""
                INSERT INTO self_service_password_logs (
                    username, method, recipient, otp_code, otp_expires_at, status,
                    ip_address, user_agent, created_at, failed_attempts
                ) VALUES ('Administrator', 'EMAIL_OTP', 'admin@corp.local', ?, ?, 'PENDING_OTP', '127.0.0.1', 'pytest', ?, 0)
            """, (admin_otp_hash, time.time() + 600, time.time()))
            admin_reset_id = cursor.lastrowid
            conn.commit()
            conn.close()

            # Wrong code -> 400 (not 403)
            res_wrong = client.post("/api/v1/self-service/password/verify-and-reset", json={
                "username": "Administrator",
                "reset_id": admin_reset_id,
                "otp_code": "000000",
                "new_password": "NewValidPassword123!"
            })
            assert res_wrong.status_code == 400, f"Expected 400 for wrong OTP on privileged account, got {res_wrong.status_code}"

            # Valid code -> post-verification privilege check triggers 403
            res_admin_reset = client.post("/api/v1/self-service/password/verify-and-reset", json={
                "username": "Administrator",
                "reset_id": admin_reset_id,
                "otp_code": real_admin_otp,
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


def test_verify_accepts_email_upn_and_case_insensitive_username():
    """
    Verifies that verify_otp_and_reset_password looks up request by reset_id ONLY
    and uses the stored username from DB, allowing the caller to provide email, UPN,
    or different capitalization without 400/404 mismatch.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))
            
            orig_lookup = ss_mod.lookup_ad_user
            orig_run_cmd = ss_mod.run_cmd
            orig_creds = ss_mod.get_ad_creds

            ss_mod.get_ad_creds = lambda: ("Administrator", "MockPass123!")
            ss_mod.lookup_ad_user = lambda u: {
                "found": True,
                "username": "johndoe",
                "email": "johndoe@example.com",
                "mobile": "+1234567890",
                "is_disabled": False,
                "is_privileged": False
            }
            executed_cmds = []
            ss_mod.run_cmd = lambda cmd, **kwargs: (executed_cmds.append(cmd) or (0, "Password changed successfully", ""))

            try:
                # 1. Insert stored row for 'johndoe'
                code_1 = "123456"
                hash_1 = hash_otp(code_1)
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO self_service_password_logs (
                        username, method, recipient, otp_code, otp_expires_at, status,
                        ip_address, user_agent, created_at, failed_attempts
                    ) VALUES ('johndoe', 'EMAIL_OTP', 'johndoe@example.com', ?, ?, 'PENDING_OTP', '127.0.0.1', 'pytest', ?, 0)
                """, (hash_1, time.time() + 600, time.time()))
                reset_id_1 = cursor.lastrowid
                conn.commit()
                conn.close()

                # Call verify with uppercase username "JOHNDOE"
                res_caps = client.post("/api/v1/self-service/password/verify-and-reset", json={
                    "username": "JOHNDOE",
                    "reset_id": reset_id_1,
                    "otp_code": code_1,
                    "new_password": "NewSecretPass123!"
                })
                assert res_caps.status_code == 200, f"Failed with uppercase username: {res_caps.text}"
                assert res_caps.json().get("status") == "success"
                assert executed_cmds[-1][0:4] == ["samba-tool", "user", "setpassword", "johndoe"]

                # 2. Call verify with email "johndoe@example.com"
                code_2 = "654321"
                hash_2 = hash_otp(code_2)
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO self_service_password_logs (
                        username, method, recipient, otp_code, otp_expires_at, status,
                        ip_address, user_agent, created_at, failed_attempts
                    ) VALUES ('johndoe', 'EMAIL_OTP', 'johndoe@example.com', ?, ?, 'PENDING_OTP', '127.0.0.1', 'pytest', ?, 0)
                """, (hash_2, time.time() + 600, time.time()))
                reset_id_2 = cursor.lastrowid
                conn.commit()
                conn.close()

                res_email = client.post("/api/v1/self-service/password/verify-and-reset", json={
                    "username": "johndoe@example.com",
                    "reset_id": reset_id_2,
                    "otp_code": code_2,
                    "new_password": "NewSecretPass123!"
                })
                assert res_email.status_code == 200, f"Failed with email: {res_email.text}"
                assert res_email.json().get("status") == "success"
                assert executed_cmds[-1][0:4] == ["samba-tool", "user", "setpassword", "johndoe"]

                # 3. Call verify with UPN "johndoe@CORP.LOCAL"
                code_3 = "789123"
                hash_3 = hash_otp(code_3)
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO self_service_password_logs (
                        username, method, recipient, otp_code, otp_expires_at, status,
                        ip_address, user_agent, created_at, failed_attempts
                    ) VALUES ('johndoe', 'EMAIL_OTP', 'johndoe@example.com', ?, ?, 'PENDING_OTP', '127.0.0.1', 'pytest', ?, 0)
                """, (hash_3, time.time() + 600, time.time()))
                reset_id_3 = cursor.lastrowid
                conn.commit()
                conn.close()

                res_upn = client.post("/api/v1/self-service/password/verify-and-reset", json={
                    "username": "johndoe@CORP.LOCAL",
                    "reset_id": reset_id_3,
                    "otp_code": code_3,
                    "new_password": "NewSecretPass123!"
                })
                assert res_upn.status_code == 200, f"Failed with UPN: {res_upn.text}"
                assert res_upn.json().get("status") == "success"
                assert executed_cmds[-1][0:4] == ["samba-tool", "user", "setpassword", "johndoe"]

            finally:
                ss_mod.lookup_ad_user = orig_lookup
                ss_mod.run_cmd = orig_run_cmd
                ss_mod.get_ad_creds = orig_creds
        finally:
            _restore_environment(orig)


def test_fake_request_ineligible_user_indistinguishable_from_real_user():
    """
    Verifies that an ineligible user's request is stored as PENDING_OTP with an unusable hash,
    and returns identical responses to a real user across 5 wrong guesses until both lock.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))
            
            # Configure SMTP and higher daily attempt limit
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("UPDATE self_service_password_settings SET email_smtp_enabled = 1, smtp_host = 'smtp.test.local', max_daily_attempts = 20, max_daily_attempts_per_ip = 50 WHERE id = 1")
            conn.commit()
            conn.close()

            orig_lookup = ss_mod.lookup_ad_user
            orig_dispatch = ss_mod.dispatch_email
            ss_mod.dispatch_email = lambda *args, **kwargs: (True, "sent")

            def mock_lookup(username):
                if username == "real_user":
                    return {
                        "found": True,
                        "username": "real_user",
                        "email": "real@example.com",
                        "mobile": None,
                        "is_disabled": False,
                        "is_privileged": False
                    }
                return {"found": False}

            ss_mod.lookup_ad_user = mock_lookup

            try:
                # 1. Request OTP for real user
                r_real = client.post("/api/v1/self-service/password/request-otp", json={"username": "real_user", "channel": "email"})
                assert r_real.status_code == 200
                reset_id_real = r_real.json()["reset_id"]

                # 2. Request OTP for ineligible/nonexistent user
                r_fake = client.post("/api/v1/self-service/password/request-otp", json={"username": "fake_user", "channel": "email"})
                assert r_fake.status_code == 200
                reset_id_fake = r_fake.json()["reset_id"]

                # Compare verify responses for attempts 1 through 4
                for attempt in range(1, 5):
                    wrong_code = f"88888{attempt}"
                    res_real = client.post("/api/v1/self-service/password/verify-and-reset", json={
                        "username": "real_user",
                        "reset_id": reset_id_real,
                        "otp_code": wrong_code,
                        "new_password": "NewPassword123!"
                    })
                    res_fake = client.post("/api/v1/self-service/password/verify-and-reset", json={
                        "username": "fake_user",
                        "reset_id": reset_id_fake,
                        "otp_code": wrong_code,
                        "new_password": "NewPassword123!"
                    })

                    assert res_real.status_code == 400
                    assert res_fake.status_code == 400
                    assert res_real.json()["detail"] == res_fake.json()["detail"]
                    assert f"{5 - attempt} attempts remaining" in res_real.json()["detail"]

                # 5th attempt: both must lock with identical message
                res_real_5 = client.post("/api/v1/self-service/password/verify-and-reset", json={
                    "username": "real_user",
                    "reset_id": reset_id_real,
                    "otp_code": "000000",
                    "new_password": "NewPassword123!"
                })
                res_fake_5 = client.post("/api/v1/self-service/password/verify-and-reset", json={
                    "username": "fake_user",
                    "reset_id": reset_id_fake,
                    "otp_code": "000000",
                    "new_password": "NewPassword123!"
                })

                assert res_real_5.status_code == 400
                assert res_fake_5.status_code == 400
                assert res_real_5.json()["detail"] == res_fake_5.json()["detail"]
                assert "locked" in res_real_5.json()["detail"].lower()

                # Verify database records for both
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                cursor.execute("SELECT status, failed_attempts FROM self_service_password_logs WHERE id = ?", (reset_id_real,))
                row_real = cursor.fetchone()
                cursor.execute("SELECT status, failed_attempts FROM self_service_password_logs WHERE id = ?", (reset_id_fake,))
                row_fake = cursor.fetchone()
                conn.close()

                assert row_real[0] == row_fake[0] == "LOCKED"
                assert row_real[1] == row_fake[1] == 5

            finally:
                ss_mod.lookup_ad_user = orig_lookup
                ss_mod.dispatch_email = orig_dispatch
        finally:
            _restore_environment(orig)


def test_nested_admin_group_membership_detection():
    """Verifies that nested admin-group membership is detected using LDAP matching rule in chain."""
    orig_run_cmd = ss_mod.run_cmd
    queried_filters = []

    def mock_run_cmd(cmd, **kwargs):
        for arg in cmd:
            if "memberOf:1.2.840.113556.1.4.1941" in arg:
                queried_filters.append(arg)
        if any("nested_admin" in arg for arg in cmd):
            return 0, "dn: CN=nested_admin,CN=Users,DC=example,DC=com\n", ""
        return 0, "", ""

    ss_mod.run_cmd = mock_run_cmd
    try:
        assert ss_mod.is_privileged_account("nested_admin", base_dn="DC=example,DC=com") is True
        assert len(queried_filters) > 0
        q = queried_filters[-1]
        assert "CN=Domain Admins,CN=Users,DC=example,DC=com" in q
        assert "CN=Enterprise Admins,CN=Users,DC=example,DC=com" in q
        assert "CN=Schema Admins,CN=Users,DC=example,DC=com" in q
        assert "CN=Administrators,CN=Builtin,DC=example,DC=com" in q

        assert ss_mod.is_privileged_account("regular_user", base_dn="DC=example,DC=com") is False
    finally:
        ss_mod.run_cmd = orig_run_cmd


def test_otp_secret_key_generation_and_file_mode():
    """Verifies that OTP key is generated as 32 random bytes and saved with mode 0600."""
    import api.core.security as sec_mod
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        test_secret_file = tmp_dir / "otp_secret"
        orig_file = sec_mod.OTP_SECRET_FILE
        orig_runtime = sec_mod._RUNTIME_OTP_KEY
        orig_cfg = sec_mod.CONFIG_DIR

        sec_mod.OTP_SECRET_FILE = test_secret_file
        sec_mod.CONFIG_DIR = tmp_dir
        sec_mod._RUNTIME_OTP_KEY = None

        try:
            assert not test_secret_file.exists()
            key1 = sec_mod.get_otp_secret_key()
            assert len(key1) == 32
            assert test_secret_file.exists()
            assert (test_secret_file.stat().st_mode & 0o777) == 0o600

            key2 = sec_mod.get_otp_secret_key()
            assert key1 == key2
        finally:
            sec_mod.OTP_SECRET_FILE = orig_file
            sec_mod._RUNTIME_OTP_KEY = orig_runtime
            sec_mod.CONFIG_DIR = orig_cfg


def test_per_ip_limit_and_per_user_limit():
    """Verifies default limits and that exceeding max_daily_attempts_per_ip triggers HTTP 429."""
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("192.168.1.100", 50000))
            
            # 1. Check default values
            settings = ss_mod.get_sspr_settings()
            assert settings.get("max_daily_attempts") == 5
            assert settings.get("max_daily_attempts_per_ip") == 50

            # 2. Update to low IP limit (2) and high user limit (10)
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("UPDATE self_service_password_settings SET max_daily_attempts = 10, max_daily_attempts_per_ip = 2, email_smtp_enabled = 1, smtp_host = 'smtp.test.local' WHERE id = 1")
            conn.commit()
            conn.close()

            orig_lookup = ss_mod.lookup_ad_user
            orig_dispatch = ss_mod.dispatch_email
            ss_mod.lookup_ad_user = lambda u: {"found": True, "username": u, "email": f"{u}@test.local", "mobile": None, "is_disabled": False, "is_privileged": False}
            ss_mod.dispatch_email = lambda *args, **kwargs: (True, "sent")

            try:
                # Two distinct users from same IP
                r1 = client.post("/api/v1/self-service/password/request-otp", json={"username": "user_one", "channel": "email"})
                assert r1.status_code == 200
                r2 = client.post("/api/v1/self-service/password/request-otp", json={"username": "user_two", "channel": "email"})
                assert r2.status_code == 200

                # Third request from same IP must hit IP rate limit 429
                r3 = client.post("/api/v1/self-service/password/request-otp", json={"username": "user_three", "channel": "email"})
                assert r3.status_code == 429
                assert "reached from this ip address" in r3.json()["detail"].lower()
            finally:
                ss_mod.lookup_ad_user = orig_lookup
                ss_mod.dispatch_email = orig_dispatch
        finally:
            _restore_environment(orig)


def test_registration_failed_attempts_carryover_and_rate_limit():
    """
    Verifies that self-registration carries failed_attempts over when the same user/mobile resubmits,
    refuses locked resubmissions, and enforces 3 SMS per hour per mobile.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("UPDATE self_registration_settings SET enabled = 1, require_mobile_otp = 1, sms_gateway_type = 'webhook', sms_gateway_url = 'http://sms.local/send' WHERE id = 1")
            conn.commit()
            conn.close()

            orig_cmd = reg_mod.run_cmd
            orig_req = reg_mod.requests.get
            reg_mod.run_cmd = lambda cmd, **kwargs: (0, "", "")
            class DummyResp:
                status_code = 200
                text = "OK"
            reg_mod.requests.get = lambda *args, **kwargs: DummyResp()

            try:
                # 1. Submit up to 3 times (the hourly limit)
                for i in range(1, 4):
                    res = client.post("/api/v1/public/register/initiate", json={
                        "username": f"reguser{i}",
                        "password": "Password123!",
                        "given_name": "Test",
                        "surname": "User",
                        "email": f"reg{i}@example.com",
                        "mobile": "+19998887777"
                    })
                    assert res.status_code == 200, f"Attempt {i} failed: {res.text}"

                # 4th submit with same mobile -> 429
                res_limit = client.post("/api/v1/public/register/initiate", json={
                    "username": "reguser4",
                    "password": "Password123!",
                    "given_name": "Test",
                    "surname": "User",
                    "email": "reg4@example.com",
                    "mobile": "+19998887777"
                })
                assert res_limit.status_code == 429
                assert "per hour" in res_limit.json()["detail"].lower()

                # 2. Test failed_attempts carryover
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO self_registrations (
                        username, email, given_name, surname, department, mobile,
                        password_hash, status, failed_attempts, created_at
                    ) VALUES ('lockeduser', 'locked@test.local', 'Lock', 'User', 'IT', '+15550001111',
                              'hash', 'LOCKED', 5, ?)
                """, (time.time(),))
                conn.commit()
                conn.close()

                # Resubmission for locked user must be rejected with 400
                res_resub = client.post("/api/v1/public/register/initiate", json={
                    "username": "lockeduser",
                    "password": "Password123!",
                    "given_name": "Lock",
                    "surname": "User",
                    "email": "locked2@test.local",
                    "mobile": "+15550001111"
                })
                assert res_resub.status_code == 400
                assert "locked" in res_resub.json()["detail"].lower()

                # 3. Test that old locked registrations (> 24 hours ago) are NOT carried over
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO self_registrations (
                        username, email, given_name, surname, department, mobile,
                        password_hash, status, failed_attempts, created_at
                    ) VALUES ('olduser', 'old@test.local', 'Old', 'User', 'IT', '+15550002222',
                              'hash', 'LOCKED', 5, ?)
                """, (time.time() - 90000,))
                conn.commit()
                conn.close()

                res_old = client.post("/api/v1/public/register/initiate", json={
                    "username": "olduser",
                    "password": "Password123!",
                    "given_name": "Old",
                    "surname": "User",
                    "email": "old2@test.local",
                    "mobile": "+15550002222"
                })
                assert res_old.status_code == 200, f"Expected 200 for registration with >24h old record, got {res_old.status_code}"

            finally:
                reg_mod.run_cmd = orig_cmd
                reg_mod.requests.get = orig_req
        finally:
            _restore_environment(orig)


def test_public_password_config_reports_only_configured_channels():
    """Verifies that /password/config reports email and SMS as available ONLY when actually configured."""
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        db_file, _, orig = _setup_test_environment(tmp_dir)
        try:
            client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

            # 1. Initially neither SMTP nor SMS is configured
            r1 = client.get("/api/v1/self-service/password/config")
            assert r1.status_code == 200
            cfg1 = r1.json()
            assert cfg1["allow_email_reset"] is False
            assert cfg1["allow_otp_reset"] is False

            # 2. Configure SMTP only
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("UPDATE self_service_password_settings SET email_smtp_enabled = 1, smtp_host = 'smtp.test.local' WHERE id = 1")
            conn.commit()
            conn.close()

            r2 = client.get("/api/v1/self-service/password/config")
            assert r2.status_code == 200
            cfg2 = r2.json()
            assert cfg2["allow_email_reset"] is True
            assert cfg2["allow_otp_reset"] is False

            # 3. Configure SMS gateway (webhook)
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("UPDATE self_service_password_settings SET sms_gateway_type = 'webhook', sms_gateway_url = 'https://sms.example.com/send' WHERE id = 1")
            conn.commit()
            conn.close()

            r3 = client.get("/api/v1/self-service/password/config")
            assert r3.status_code == 200
            cfg3 = r3.json()
            assert cfg3["allow_email_reset"] is True
            assert cfg3["allow_otp_reset"] is True
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
    print("Running test_verify_accepts_email_upn_and_case_insensitive_username...")
    test_verify_accepts_email_upn_and_case_insensitive_username()
    print("Running test_fake_request_ineligible_user_indistinguishable_from_real_user...")
    test_fake_request_ineligible_user_indistinguishable_from_real_user()
    print("Running test_nested_admin_group_membership_detection...")
    test_nested_admin_group_membership_detection()
    print("Running test_otp_secret_key_generation_and_file_mode...")
    test_otp_secret_key_generation_and_file_mode()
    print("Running test_per_ip_limit_and_per_user_limit...")
    test_per_ip_limit_and_per_user_limit()
    print("Running test_registration_failed_attempts_carryover_and_rate_limit...")
    test_registration_failed_attempts_carryover_and_rate_limit()
    print("Running test_public_password_config_reports_only_configured_channels...")
    test_public_password_config_reports_only_configured_channels()
    print("ALL SSPR HARDENING TESTS PASSED SUCCESSFULLY!")
