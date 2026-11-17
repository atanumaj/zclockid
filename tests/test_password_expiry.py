"""
Tests for v1.4.8 Password Expiry Policy, PSOs, smbclient Error Mapping,
smbpasswd Stdin Verification, and Expiry Reminders Idempotency.
"""

import os
import time
import subprocess
import sqlite3
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.main import app
from api.core.config import DB_PATH
from api.db.init_db import init_db
from api.services.samba_service import provision_user_in_ad
from api.services.password_expiry_service import (
    ensure_selfreg_group_and_pso,
    get_user_password_info,
    get_password_expiry_report,
    apply_bulk_expiry_policy,
    run_password_expiry_reminders
)


import api.services.security_service as sec_svc


@pytest.fixture(autouse=True)
def allow_testclient_in_tests(monkeypatch):
    """Allows testclient / 127.0.0.1 in the security baseline firewall check during tests."""
    orig_is_ip_allowed = sec_svc.is_ip_allowed
    monkeypatch.setattr(
        sec_svc,
        "is_ip_allowed",
        lambda ip, allowed: True if ip in ("testclient", "127.0.0.1") else orig_is_ip_allowed(ip, allowed)
    )
    import api.main as main_mod
    monkeypatch.setattr(
        main_mod,
        "is_ip_allowed",
        lambda ip, allowed: True if ip in ("testclient", "127.0.0.1") else orig_is_ip_allowed(ip, allowed)
    )


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Initializes isolated database and updates directory for tests."""
    db_file = tmp_path / "test_zclockid.db"
    monkeypatch.setattr("api.core.config.DB_PATH", db_file)
    monkeypatch.setattr("api.db.init_db.DB_PATH", db_file)
    monkeypatch.setattr("api.routers.auth.DB_PATH", db_file)
    monkeypatch.setattr("api.routers.users.DB_PATH", db_file)
    monkeypatch.setattr("api.routers.self_service.DB_PATH", db_file)
    monkeypatch.setattr("api.routers.registration.DB_PATH", db_file)
    monkeypatch.setattr("api.services.password_expiry_service.DB_PATH", db_file)
    monkeypatch.setattr("api.services.registration_purge.DB_PATH", db_file)
    monkeypatch.setattr("api.services.security_service.DB_PATH", db_file)

    updates_dir = tmp_path / "updates"
    updates_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ZCLOCKID_UPDATES_DIR", str(updates_dir))
    monkeypatch.setattr("api.core.config.UPDATES_DIR", updates_dir)

    init_db(db_file)

    # Ensure SSPR settings have allow_old_password_reset=1 and enabled=1
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE self_service_password_settings
        SET enabled = 1, allow_old_password_reset = 1, require_complexity = 1, min_password_length = 8
        WHERE id = 1
    """)
    conn.commit()
    conn.close()

    return db_file


def get_auth_token(role="fulladmin", username="admin"):
    import api.core.config as cfg
    conn = sqlite3.connect(cfg.DB_PATH)
    cursor = conn.cursor()
    token = f"test_token_{role}_{username}"
    now = time.time()
    cursor.execute("""
        INSERT INTO sessions (token, username, role, ip_address, user_agent, created_at, last_active, expires_at)
        VALUES (?, ?, ?, '127.0.0.1', 'pytest', ?, ?, ?)
    """, (token, username, role, now, now, now + 3600))
    conn.commit()
    conn.close()
    return token


# =============================================================================
# Invariant 1: No --noexpiry call by default
# =============================================================================
def test_invariant_1_no_noexpiry_call_by_default():
    """Verify that user provisioning does NOT call samba-tool user setexpiry --noexpiry unless explicitly requested."""
    commands_run = []

    def fake_run_cmd(cmd, timeout=10, input_data=None):
        commands_run.append(list(cmd))
        if cmd[0] == "ldbsearch":
            return 0, "sAMAccountName: admin\n", ""
        return 0, "", ""

    with patch("api.services.samba_service.run_cmd", side_effect=fake_run_cmd), \
         patch("api.services.samba_service.get_license_status", return_value={"can_create_user": True, "max_users": 200}), \
         patch("api.services.samba_service.get_ad_creds", return_value=("Administrator", "AdminP@ss2026!")), \
         patch("api.services.samba_service.update_user_upn", return_value=True), \
         patch("api.services.password_expiry_service.add_user_to_selfreg_group", return_value=True):

        # 1. Default provisioning: password_never_expires = False
        provision_user_in_ad(
            username="test_user_std",
            password="SecureP@ssw0rd2026!",
            given_name="Standard",
            surname="User",
            email="std@example.com",
            mobile="+1234567890",
            department="Engineering",
            is_self_registered=False,
            password_never_expires=False
        )

        # Assert no call with '--noexpiry'
        noexpiry_calls = [c for c in commands_run if "--noexpiry" in c]
        assert len(noexpiry_calls) == 0, f"Expected no '--noexpiry' call, but found: {noexpiry_calls}"

        # 2. Provisioning with password_never_expires = True
        commands_run.clear()
        provision_user_in_ad(
            username="test_user_never",
            password="SecureP@ssw0rd2026!",
            given_name="Never",
            surname="Expire",
            email="never@example.com",
            mobile="+1234567890",
            department="Engineering",
            is_self_registered=False,
            password_never_expires=True
        )

        noexpiry_calls = [c for c in commands_run if "--noexpiry" in c]
        assert len(noexpiry_calls) == 1, "Expected exactly 1 '--noexpiry' call when password_never_expires=True"
        assert noexpiry_calls[0][1:4] == ["user", "setexpiry", "test_user_never"]


# =============================================================================
# Invariant 2: Group membership and PSO applied
# =============================================================================
def test_invariant_2_group_membership_and_pso_applied():
    """Verify group ZclockID-SelfRegistered and PSO ZclockID-SelfReg-PSO are created and applied."""
    commands_run = []

    def fake_run_cmd(cmd, timeout=10, input_data=None):
        cmd_list = list(cmd)
        commands_run.append(cmd_list)
        if cmd_list[0] == "ldbsearch":
            if "ZclockID-SelfRegistered" in " ".join(cmd_list):
                return 1, "", "not found"
            # Return one self-registered user to backfill
            return 0, "sAMAccountName: legacy_selfreg_user\n\n", ""
        if "pso" in cmd_list and "show" in cmd_list:
            return 1, "", "PSO does not exist"
        return 0, "", ""

    with patch("api.services.password_expiry_service.run_cmd", side_effect=fake_run_cmd), \
         patch("api.services.password_expiry_service.get_ad_creds", return_value=("Administrator", "AdminP@ss2026!")):

        res = ensure_selfreg_group_and_pso(max_pwd_age_days=180)
        assert res["status"] == "success"
        assert res["pso"] == "ZclockID-SelfReg-PSO"
        assert res["max_pwd_age_days"] == 180

        # Verify group add command was called
        grp_add_calls = [c for c in commands_run if "group" in c and "add" in c and "ZclockID-SelfRegistered" in c]
        assert len(grp_add_calls) >= 1

        # Verify legacy user was backfilled
        backfill_calls = [c for c in commands_run if "group" in c and "addmembers" in c and "legacy_selfreg_user" in c]
        assert len(backfill_calls) >= 1

        # Verify PSO was created with precedence 10 and max-pwd-age 180
        pso_create_calls = [c for c in commands_run if "pso" in c and "create" in c and "ZclockID-SelfReg-PSO" in c]
        assert len(pso_create_calls) >= 1
        assert "10" in pso_create_calls[0]
        assert "--max-pwd-age=180" in pso_create_calls[0]

        # Verify PSO was applied to ZclockID-SelfRegistered
        pso_apply_calls = [c for c in commands_run if "pso" in c and "apply" in c and "ZclockID-SelfReg-PSO" in c]
        assert len(pso_apply_calls) >= 1
        assert "ZclockID-SelfRegistered" in pso_apply_calls[0]


def test_invariant_2b_domain_functional_level_warning_never_fails_creation():
    """If the domain functional level doesn't support PSOs, logs warning but does not fail account creation."""
    def fake_run_cmd(cmd, timeout=10, input_data=None):
        cmd_list = list(cmd)
        if "pso" in cmd_list and "show" in cmd_list:
            return 1, "", "PSO does not exist"
        if "pso" in cmd_list and "create" in cmd_list:
            return 1, "", "ERROR: The domain functional level does not support Password Settings Objects."
        if cmd_list[0] == "ldbsearch":
            return 0, "sAMAccountName: admin\n", ""
        return 0, "", ""

    with patch("api.services.password_expiry_service.run_cmd", side_effect=fake_run_cmd), \
         patch("api.services.password_expiry_service.get_ad_creds", return_value=("Administrator", "AdminP@ss2026!")), \
         patch("api.services.samba_service.run_cmd", side_effect=fake_run_cmd), \
         patch("api.services.samba_service.get_license_status", return_value={"can_create_user": True, "max_users": 200}), \
         patch("api.services.samba_service.get_ad_creds", return_value=("Administrator", "AdminP@ss2026!")):

        # ensure_selfreg_group_and_pso returns warning, doesn't raise
        pso_res = ensure_selfreg_group_and_pso(max_pwd_age_days=365)
        assert pso_res["status"] == "warning"
        assert "functional level" in pso_res.get("warning", "").lower()

        # Provisioning succeeds without crashing
        ok = provision_user_in_ad(
            username="selfreg_user_fl_test",
            password="SecureP@ssw0rd2026!",
            given_name="Self",
            surname="Reg",
            email="self@example.com",
            mobile="+1234567890",
            department="Engineering",
            is_self_registered=True
        )
        assert ok is True


# =============================================================================
# Invariant 3: Mocked smbclient outputs map correctly, expired writes no failed row
# =============================================================================
def test_invariant_3_smbclient_output_mapping_and_no_failed_login_row():
    """Verify smbclient NT_STATUS codes are mapped to 403, and expired case writes no failed-login row."""
    client = TestClient(app)

    # 1. NT_STATUS_PASSWORD_EXPIRED -> 403 {"code": "PASSWORD_EXPIRED"}, no failed login row
    mock_proc_expired = MagicMock()
    mock_proc_expired.returncode = 1
    mock_proc_expired.stdout = b""
    mock_proc_expired.stderr = b"session setup failed: NT_STATUS_PASSWORD_EXPIRED\n"

    with patch("subprocess.run", return_value=mock_proc_expired):
        res = client.post("/api/v1/auth/login", json={"username": "expired_user", "password": "ExpiredP@ss1!"})
        assert res.status_code == 403
        data = res.json()
        assert data.get("code") == "PASSWORD_EXPIRED"

        # Check DB: no failed-login row must exist for expired_user
        import api.core.config as cfg
        conn = sqlite3.connect(cfg.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM failed_login_attempts WHERE username = 'expired_user'")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 0, f"Expected 0 failed_login_attempts for expired password, found {count}"

    # 2. NT_STATUS_PASSWORD_MUST_CHANGE -> 403 {"code": "PASSWORD_EXPIRED"}, no failed login row
    mock_proc_must_change = MagicMock()
    mock_proc_must_change.returncode = 1
    mock_proc_must_change.stdout = b"session setup failed: NT_STATUS_PASSWORD_MUST_CHANGE\n"
    mock_proc_must_change.stderr = b""

    with patch("subprocess.run", return_value=mock_proc_must_change):
        res = client.post("/api/v1/auth/login", json={"username": "must_change_user", "password": "OldP@ss1!"})
        assert res.status_code == 403
        data = res.json()
        assert data.get("code") == "PASSWORD_EXPIRED"

        conn = sqlite3.connect(cfg.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM failed_login_attempts WHERE username = 'must_change_user'")
        assert cursor.fetchone()[0] == 0
        conn.close()

    # 3. NT_STATUS_ACCOUNT_EXPIRED -> 403 {"code": "ACCOUNT_EXPIRED"}
    mock_proc_acct_exp = MagicMock()
    mock_proc_acct_exp.returncode = 1
    mock_proc_acct_exp.stdout = b"session setup failed: NT_STATUS_ACCOUNT_EXPIRED\n"
    mock_proc_acct_exp.stderr = b""

    with patch("subprocess.run", return_value=mock_proc_acct_exp):
        res = client.post("/api/v1/auth/login", json={"username": "acct_exp_user", "password": "SomeP@ss1!"})
        assert res.status_code == 403
        assert res.json().get("code") == "ACCOUNT_EXPIRED"

    # 4. NT_STATUS_ACCOUNT_DISABLED -> 403 {"code": "ACCOUNT_DISABLED"}
    mock_proc_disabled = MagicMock()
    mock_proc_disabled.returncode = 1
    mock_proc_disabled.stdout = b"session setup failed: NT_STATUS_ACCOUNT_DISABLED\n"
    mock_proc_disabled.stderr = b""

    with patch("subprocess.run", return_value=mock_proc_disabled):
        res = client.post("/api/v1/auth/login", json={"username": "dis_user", "password": "SomeP@ss1!"})
        assert res.status_code == 403
        assert res.json().get("code") == "ACCOUNT_DISABLED"

    # 5. NT_STATUS_ACCOUNT_LOCKED_OUT -> 403 {"code": "ACCOUNT_LOCKED_OUT"}
    mock_proc_lockout = MagicMock()
    mock_proc_lockout.returncode = 1
    mock_proc_lockout.stdout = b"session setup failed: NT_STATUS_ACCOUNT_LOCKED_OUT\n"
    mock_proc_lockout.stderr = b""

    with patch("subprocess.run", return_value=mock_proc_lockout):
        res = client.post("/api/v1/auth/login", json={"username": "locked_user", "password": "SomeP@ss1!"})
        assert res.status_code == 403
        assert res.json().get("code") == "ACCOUNT_LOCKED_OUT"

    # 6. Generic invalid credentials -> 401 Unauthorized, writes failed login row
    mock_proc_bad_creds = MagicMock()
    mock_proc_bad_creds.returncode = 1
    mock_proc_bad_creds.stdout = b"session setup failed: NT_STATUS_LOGON_FAILURE\n"
    mock_proc_bad_creds.stderr = b""

    with patch("subprocess.run", return_value=mock_proc_bad_creds):
        res = client.post("/api/v1/auth/login", json={"username": "bad_cred_user", "password": "WrongP@ss1!"})
        assert res.status_code == 401
        assert "Invalid username or password" in res.json().get("detail", "")

        conn = sqlite3.connect(cfg.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM failed_login_attempts WHERE username = 'bad_cred_user'")
        assert cursor.fetchone()[0] == 1
        conn.close()


# =============================================================================
# Invariant 4: smbpasswd gets the password only through stdin
# =============================================================================
def test_invariant_4_smbpasswd_stdin_only_in_change_with_old():
    """Verify smbpasswd receives old and new passwords strictly via stdin, never in command line arguments."""
    client = TestClient(app)

    captured_calls = []

    def fake_run_cmd(cmd, timeout=15, input_data=None):
        captured_calls.append({"cmd": list(cmd), "input_data": input_data})
        return 0, "Password changed for user test_change_user on 127.0.0.1.\n", ""

    old_pwd = "OldP@ssw0rd2026!"
    new_pwd = "BrandNewP@ssw0rd2026!"

    with patch("api.routers.self_service.run_cmd", side_effect=fake_run_cmd), \
         patch("api.routers.self_service.lookup_ad_user", return_value={"found": True, "username": "test_change_user", "is_privileged": False}):

        res = client.post("/api/v1/self-service/password/change-with-old", json={
            "username": "test_change_user",
            "old_password": old_pwd,
            "new_password": new_pwd
        })

        assert res.status_code == 200
        smb_calls = [c for c in captured_calls if c["cmd"][0] == "smbpasswd"]
        assert len(smb_calls) == 1
        call = smb_calls[0]
        cmd = call["cmd"]
        stdin_data = call["input_data"]

        # 1. Assert command arguments are strictly ["smbpasswd", "-r", "127.0.0.1", "-U", "test_change_user", "-s"]
        assert cmd == ["smbpasswd", "-r", "127.0.0.1", "-U", "test_change_user", "-s"]
        assert old_pwd not in " ".join(cmd)
        assert new_pwd not in " ".join(cmd)

        # 2. Assert input_data contains old\nnew\nnew\n
        expected_stdin = f"{old_pwd}\n{new_pwd}\n{new_pwd}\n"
        assert stdin_data == expected_stdin


# =============================================================================
# Invariant 5: Reminders aren't sent twice
# =============================================================================
def test_invariant_5_reminders_not_sent_twice(monkeypatch):
    """Verify daily reminder job notifies users at 14, 7, and 1 days before expiry, exactly once per threshold."""
    # Mock AD returning a self-registered user whose password expires in 10 days (threshold = 14)
    # FileTime: 134393759554375688
    fake_pwd_last_set = 134390000000000000 # fixed timestamp

    # Current simulated time: 10 days before expiry
    # Unix timestamp of fake_pwd_last_set:
    pwd_epoch = (fake_pwd_last_set - 116444736000000000) / 10000000.0
    # If max-pwd-age is 365 days:
    expires_epoch = pwd_epoch + (365 * 86400.0)

    # 1. At 10 days before expiry (matches 14-day threshold: 7 < days <= 14)
    simulated_now_1 = expires_epoch - (10 * 86400.0)

    def fake_run_cmd(cmd, timeout=10, input_data=None):
        cmd_list = list(cmd)
        if cmd_list[0] == "ldbsearch":
            return 0, (
                "dn: CN=rem_user,CN=Users,DC=inet,DC=net\n"
                "sAMAccountName: rem_user\n"
                "mail: rem_user@example.com\n"
                "telephoneNumber: +1999888777\n"
                "userAccountControl: 512\n"
                f"pwdLastSet: {fake_pwd_last_set}\n\n"
            ), ""
        return 0, "", ""

    dispatched_emails = []
    def fake_dispatch_email(to_email, subject, body, settings):
        dispatched_emails.append({"to": to_email, "subject": subject, "body": body})
        return True, "Email sent"

    with patch("api.services.password_expiry_service.run_cmd", side_effect=fake_run_cmd), \
         patch("api.services.password_expiry_service.get_user_password_info", return_value={
             "username": "rem_user",
             "never_expires": False,
             "is_expired": False,
             "days_remaining": 10.0,
             "pwd_last_set": fake_pwd_last_set
         }), \
         patch("api.routers.registration.dispatch_email", side_effect=fake_dispatch_email), \
         patch("api.routers.registration.dispatch_sms", return_value=(True, "SMS sent")):

        # First run: should send reminder for 14-day threshold
        res1 = run_password_expiry_reminders(current_time=simulated_now_1)
        assert res1["status"] == "completed"
        assert res1["reminders_sent"] == 1
        assert len(dispatched_emails) == 1
        assert "10 days" in dispatched_emails[0]["body"]

        # Second run immediately on same day: MUST NOT SEND AGAIN (idempotent)
        res2 = run_password_expiry_reminders(current_time=simulated_now_1)
        assert res2["status"] == "completed"
        assert res2["reminders_sent"] == 0
        assert len(dispatched_emails) == 1 # still only 1 email sent

        # Third run at 5 days before expiry (matches 7-day threshold: 1 < days <= 7)
        simulated_now_2 = expires_epoch - (5 * 86400.0)
        with patch("api.services.password_expiry_service.get_user_password_info", return_value={
            "username": "rem_user",
            "never_expires": False,
            "is_expired": False,
            "days_remaining": 5.0,
            "pwd_last_set": fake_pwd_last_set
        }):
            res3 = run_password_expiry_reminders(current_time=simulated_now_2)
            assert res3["reminders_sent"] == 1
            assert len(dispatched_emails) == 2
            assert "5 days" in dispatched_emails[1]["body"]

            # Repeat run at 5 days: MUST NOT SEND AGAIN
            res4 = run_password_expiry_reminders(current_time=simulated_now_2)
            assert res4["reminders_sent"] == 0
            assert len(dispatched_emails) == 2


# =============================================================================
# Invariant 6: Expiry report and bulk apply exclude service accounts
# =============================================================================
def test_invariant_6_expiry_report_and_bulk_apply_exclude_service_accounts():
    """Verify Expiry Policy Report and bulk Apply exclude Administrator and service accounts."""
    client = TestClient(app)
    token = get_auth_token("fulladmin")
    headers = {"Authorization": f"Bearer {token}"}

    fake_ldb_output = (
        "sAMAccountName: Administrator\nuserAccountControl: 66048\n\n"
        "sAMAccountName: krbtgt\nuserAccountControl: 66050\n\n"
        "sAMAccountName: svc_backup\nuserAccountControl: 66048\n\n"
        "sAMAccountName: regular_alice\nuserAccountControl: 66048\npwdLastSet: 134393759550000000\n\n"
        "sAMAccountName: regular_bob\nuserAccountControl: 512\npwdLastSet: 134393759550000000\n\n"
    )

    def fake_run_cmd(cmd, timeout=10, input_data=None):
        cmd_list = list(cmd)
        if cmd_list[0] == "ldbsearch":
            return 0, fake_ldb_output, ""
        return 0, "", ""

    with patch("api.services.password_expiry_service.run_cmd", side_effect=fake_run_cmd):
        res_rep = client.get("/api/v1/users/expiry-policy/report", headers=headers)
        assert res_rep.status_code == 200
        rep_data = res_rep.json()
        assert rep_data["total_users"] == 5
        # Administrator, krbtgt, svc_backup are excluded
        assert "Administrator" in rep_data["excluded_users"]
        assert "svc_backup" in rep_data["excluded_users"]
        # Only regular_alice is eligible (regular_bob has 512, already compliant)
        assert rep_data["eligible_count"] == 1
        assert rep_data["eligible_users"][0]["username"] == "regular_alice"

    # Test Bulk Apply
    with patch("api.services.password_expiry_service.get_password_expiry_report", return_value=rep_data), \
         patch("api.services.password_expiry_service.run_cmd", return_value=(0, "dn: CN=regular_alice,CN=Users,DC=inet,DC=net\n", "")), \
         patch("subprocess.run", return_value=MagicMock(returncode=0)):

        res_apply = client.post("/api/v1/users/expiry-policy/apply", headers=headers)
        assert res_apply.status_code == 200
        data_apply = res_apply.json()
        assert data_apply["status"] == "success"
        assert data_apply["modified_count"] == 1
        assert "regular_alice" in data_apply["modified_users"]
        # Administrator and svc_backup must NEVER be modified
        assert "Administrator" not in data_apply["modified_users"]
        assert "svc_backup" not in data_apply["modified_users"]
