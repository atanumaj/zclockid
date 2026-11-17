"""
Unit & Invariant Tests for v1.4.7 Self-Registration Hardening & Secret Box
========================================================================
Covers the 12 required test invariants:
1. Full SQLite dump contains test password nowhere; password_enc starts with 'v1:'.
2. OTP lifecycle: pending at +9 min, EXPIRED_OTP with password_enc/otp_code NULL at +11 min, deleted at +25 h.
3. Resend OTP extends expiry.
4. After lockout (5 attempts), resubmission carries failed_attempts over (blocked).
5. Approval TTL: pending at day 6, EXPIRED_APPROVAL with password_enc NULL at day 7 + 1s.
6. Clock guard: mass expiry (>10 rows / >20%) trips guard; POST /registrations/approval-purge/force forces expiry.
7. Approve and Reject both set password_enc = NULL.
8. Key rotation: ciphertext encrypted with k1 remains decryptable after k2 is created.
9. Tampered ciphertext marks request as ERROR_REREGISTER and logs audit event.
10. Password never appears in run_cmd argv during AD provisioning.
11. Takeover prevention: different mobile returns 409; PENDING_APPROVAL row untouched.
12. Backup round-trip with passphrase restores keys; wrong passphrase returns HTTP 400 clear error.
"""

import os
import re
import time
import json
import sqlite3
import shutil
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.core.config import CONFIG_DIR, DATA_DIR, DB_PATH
import api.core.secret_box as secret_box
import api.services.registration_purge as reg_purge
import api.routers.registration as reg_mod
import api.services.samba_service as samba_svc
import api.services.system_service as sys_svc
from api.db.init_db import init_db

CAPTURED_OTPS = {}

@pytest.fixture(autouse=True)
def setup_isolated_env(tmp_path, monkeypatch):
    """Configures isolated test environment for config, data, and database."""
    global CAPTURED_OTPS
    CAPTURED_OTPS = {}

    test_conf = tmp_path / "config"
    test_data = tmp_path / "data"
    test_conf.mkdir(parents=True, exist_ok=True)
    test_data.mkdir(parents=True, exist_ok=True)
    test_db = test_data / "zclockid.db"

    import api.core.config as core_config
    monkeypatch.setattr(core_config, "CONFIG_DIR", test_conf)
    monkeypatch.setattr(core_config, "DATA_DIR", test_data)
    monkeypatch.setattr(core_config, "DB_PATH", test_db)
    monkeypatch.setattr(core_config, "BACKUP_DIR", test_data / "backups")

    monkeypatch.setenv("ZCLOCKID_REG_KEYS_DIR", str(test_conf / "registration_keys"))
    monkeypatch.setattr(reg_purge, "DATA_DIR", test_data)
    monkeypatch.setattr(reg_purge, "DB_PATH", test_db)
    monkeypatch.setattr(reg_purge, "PURGE_LOCK_FILE", test_data / "purge.lock")
    monkeypatch.setattr(reg_mod, "DB_PATH", test_db)

    import api.routers.auth as auth_router
    monkeypatch.setattr(auth_router, "DB_PATH", test_db)

    import api.routers.system as sys_router
    monkeypatch.setattr(sys_router, "DB_PATH", test_db)
    monkeypatch.setattr(sys_router, "BACKUP_DIR", test_data / "backups")

    # Allow testclient IP
    monkeypatch.setattr("api.main.is_ip_allowed", lambda ip, allowed: True)
    monkeypatch.setattr("api.services.security_service.is_ip_allowed", lambda ip, allowed: True)

    # Initialize SQLite database with fresh schema
    monkeypatch.setattr("api.db.init_db.DB_PATH", test_db)
    init_db()

    # Configure settings for test (require OTP verification, manual approval)
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE self_registration_settings
        SET enabled = 1, require_mobile_otp = 1, auto_approve_with_otp = 0,
            sms_gateway_type = 'webhook', sms_gateway_url = 'http://localhost/sms',
            otp_expiry_minutes = 10, registration_approval_ttl_days = 7
        WHERE id = 1
    """)
    conn.commit()
    conn.close()

    # Capture SMS OTP and mock samba list
    def mock_dispatch_sms(mobile, msg, settings):
        m = re.search(r"\b(\d{6})\b", msg)
        if m:
            clean_m = re.sub(r"[^\d+]", "", mobile)
            CAPTURED_OTPS[clean_m] = m.group(1)
        return (True, "Simulated SMS sent")

    monkeypatch.setattr(reg_mod, "dispatch_sms", mock_dispatch_sms)

    orig_run_cmd = sys_svc.run_cmd
    def mock_sys_run_cmd(cmd, timeout=30, input_data=None):
        if len(cmd) >= 3 and cmd[0] == "samba-tool" and cmd[1] == "user" and cmd[2] == "list":
            return (0, "", "")
        return orig_run_cmd(cmd, timeout=timeout, input_data=input_data)
    monkeypatch.setattr(sys_svc, "run_cmd", mock_sys_run_cmd)
    monkeypatch.setattr(reg_mod, "run_cmd", mock_sys_run_cmd)

    yield {
        "conf": test_conf,
        "data": test_data,
        "db": test_db
    }


def _get_admin_token(db_path):
    import secrets
    token = secrets.token_hex(32)
    conn = sqlite3.connect(db_path)
    now = time.time()
    conn.execute("""
        INSERT INTO sessions (token, username, role, created_at, expires_at, last_active)
        VALUES (?, 'admin', 'fulladmin', ?, ?, ?)
    """, (token, now, now + 3600, now))
    conn.commit()
    conn.close()
    return token


def test_invariant_1_password_encrypted_and_dump_clean(setup_isolated_env):
    """Invariant 1: SQLite dump contains test password nowhere; password_enc starts with 'v1:'."""
    client = TestClient(app)
    test_pw = "SuperSecretPlainTextPassword123!"

    resp = client.post("/api/v1/self-registration/submit", json={
        "username": "jdoe_inv1",
        "given_name": "John",
        "surname": "Doe",
        "email": "jdoe_inv1@example.com",
        "mobile": "+1234567890",
        "password": test_pw,
        "department": "Engineering"
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "otp_required"
    reg_id = data["registration_id"]

    db_path = setup_isolated_env["db"]
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT password_enc, password_hash FROM self_registrations WHERE id = ?", (reg_id,))
    row = cursor.fetchone()
    assert row is not None
    password_enc, password_hash = row

    assert password_hash is None
    assert password_enc is not None
    assert password_enc.startswith("v1:")

    # Ensure full database SQL dump contains test_pw nowhere
    dump_text = "\n".join(conn.iterdump())
    assert test_pw not in dump_text
    conn.close()


def test_invariant_2_otp_lifecycle_and_auto_purge(setup_isolated_env, monkeypatch):
    """Invariant 2: Pending at +9 min, EXPIRED_OTP with password/otp NULL at +11 min, deleted at +25 h."""
    client = TestClient(app)
    start_time = 1700000000.0

    monkeypatch.setattr(time, "time", lambda: start_time)

    resp = client.post("/api/v1/self-registration/submit", json={
        "username": "jdoe_inv2",
        "given_name": "John",
        "surname": "Doe",
        "email": "jdoe_inv2@example.com",
        "mobile": "+1234567890",
        "password": "Password123!",
        "department": "Engineering"
    })
    assert resp.status_code == 200
    reg_id = resp.json()["registration_id"]

    db_path = setup_isolated_env["db"]

    # At +9 minutes: still PENDING_OTP, password_enc present
    t_9m = start_time + 9 * 60
    reg_purge.run_registration_purge(current_time=t_9m)
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT status, password_enc, otp_code FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()
    conn.close()
    assert row[0] == "PENDING_OTP"
    assert row[1] is not None
    assert row[2] is not None

    # At +11 minutes: past 10m expiry + 60s grace -> EXPIRED_OTP, secrets nulled
    t_11m = start_time + 11 * 60 + 5
    purge_res = reg_purge.run_registration_purge(current_time=t_11m)
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT status, password_enc, otp_code, otp_expires_at FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()
    conn.close()
    assert row[0] == "EXPIRED_OTP"
    assert row[1] is None
    assert row[2] is None

    # At +25 hours: stub deleted
    t_25h = start_time + 25 * 3600
    reg_purge.run_registration_purge(current_time=t_25h)
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT status FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()
    conn.close()
    assert row is None


def test_invariant_3_resend_extends_otp_expiry(setup_isolated_env, monkeypatch):
    """Invariant 3: Resend extends OTP expiry based on otp_expiry_minutes."""
    client = TestClient(app)
    start_time = 1700000000.0
    monkeypatch.setattr(time, "time", lambda: start_time)

    resp = client.post("/api/v1/self-registration/submit", json={
        "username": "jdoe_inv3",
        "given_name": "John",
        "surname": "Doe",
        "email": "jdoe_inv3@example.com",
        "mobile": "+1234567890",
        "password": "Password123!",
        "department": "Engineering"
    })
    assert resp.status_code == 200
    reg_id = resp.json()["registration_id"]

    conn = sqlite3.connect(setup_isolated_env["db"])
    exp1 = conn.execute("SELECT otp_expires_at FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()[0]
    conn.close()
    assert exp1 == start_time + 600

    # Advance 4 minutes and resend
    t_4m = start_time + 240
    monkeypatch.setattr(time, "time", lambda: t_4m)

    resend_resp = client.post("/api/v1/self-registration/resend-otp", json={"registration_id": reg_id})
    assert resend_resp.status_code == 200

    conn = sqlite3.connect(setup_isolated_env["db"])
    exp2 = conn.execute("SELECT otp_expires_at FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()[0]
    conn.close()
    assert exp2 == t_4m + 600
    assert exp2 > exp1


def test_invariant_4_lockout_carries_over_on_resubmit(setup_isolated_env, monkeypatch):
    """Invariant 4: After lockout (5 attempts), resubmit carries failed_attempts over and fails with 400."""
    client = TestClient(app)
    start_time = 1700000000.0
    monkeypatch.setattr(time, "time", lambda: start_time)

    resp = client.post("/api/v1/self-registration/submit", json={
        "username": "jdoe_inv4",
        "given_name": "John",
        "surname": "Doe",
        "email": "jdoe_inv4@example.com",
        "mobile": "+1234567890",
        "password": "Password123!",
        "department": "Engineering"
    })
    assert resp.status_code == 200
    reg_id = resp.json()["registration_id"]

    # Fail OTP 5 times
    for _ in range(5):
        resp = client.post("/api/v1/self-registration/verify-otp", json={
            "registration_id": reg_id,
            "otp_code": "000000"
        })
    assert resp.status_code == 400
    assert "locked" in resp.json()["detail"].lower()

    # Verify LOCKED status in DB
    conn = sqlite3.connect(setup_isolated_env["db"])
    status = conn.execute("SELECT status, failed_attempts FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()
    conn.close()
    assert status[0] == "LOCKED"
    assert status[1] == 5

    # Resubmitting within 24h carryover window must fail with 400 lockout error
    resubmit_resp = client.post("/api/v1/self-registration/submit", json={
        "username": "jdoe_inv4",
        "given_name": "John",
        "surname": "Doe",
        "email": "jdoe_inv4@example.com",
        "mobile": "+1234567890",
        "password": "Password123!",
        "department": "Engineering"
    })
    assert resubmit_resp.status_code == 400
    assert "locked" in resubmit_resp.json()["detail"].lower()


def test_invariant_5_approval_ttl_expiry(setup_isolated_env, monkeypatch):
    """Invariant 5: Approval TTL: pending at day 6, EXPIRED_APPROVAL at day 7 + 1s with secrets nulled."""
    client = TestClient(app)
    start_time = 1700000000.0
    monkeypatch.setattr(time, "time", lambda: start_time)

    resp = client.post("/api/v1/self-registration/submit", json={
        "username": "jdoe_inv5",
        "given_name": "John",
        "surname": "Doe",
        "email": "jdoe_inv5@example.com",
        "mobile": "+1234567890",
        "password": "Password123!",
        "department": "Engineering"
    })
    assert resp.status_code == 200
    reg_id = resp.json()["registration_id"]

    otp = CAPTURED_OTPS["+1234567890"]
    v_resp = client.post("/api/v1/self-registration/verify-otp", json={
        "registration_id": reg_id,
        "otp_code": otp
    })
    print("v_resp response:", v_resp.status_code, v_resp.text)
    assert v_resp.status_code == 200

    conn = sqlite3.connect(setup_isolated_env["db"])
    status = conn.execute("SELECT status FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()[0]
    conn.close()
    assert status == "PENDING_APPROVAL"

    # Day 6: still PENDING_APPROVAL
    t_day6 = start_time + 6 * 86400
    reg_purge.run_registration_purge(current_time=t_day6)
    conn = sqlite3.connect(setup_isolated_env["db"])
    row = conn.execute("SELECT status, password_enc FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()
    conn.close()
    assert row[0] == "PENDING_APPROVAL"
    assert row[1] is not None

    # Day 7 + 1s: EXPIRED_APPROVAL, password_enc nulled
    t_day7_1s = start_time + 7 * 86400 + 1
    reg_purge.run_registration_purge(current_time=t_day7_1s)
    conn = sqlite3.connect(setup_isolated_env["db"])
    row = conn.execute("SELECT status, password_enc FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()
    conn.close()
    assert row[0] == "EXPIRED_APPROVAL"
    assert row[1] is None


def test_invariant_6_clock_guard_trips_and_force_purge(setup_isolated_env, monkeypatch):
    """Invariant 6: >10 candidates jump trips clock guard; force purge expires them."""
    client = TestClient(app)
    start_time = 1700000000.0
    monkeypatch.setattr(time, "time", lambda: start_time)

    # Insert 12 pending approval records
    conn = sqlite3.connect(setup_isolated_env["db"])
    cursor = conn.cursor()
    for i in range(12):
        u = f"user_cg_{i}"
        cursor.execute("""
            INSERT INTO self_registrations (
                username, email, given_name, surname, mobile, status, created_at,
                otp_verified_at, password_enc
            ) VALUES (?, ?, 'User', ?, ?, 'PENDING_APPROVAL', ?, ?, 'v1:dummy:enc')
        """, (u, f"{u}@example.com", f"CG {i}", f"+100000{i}", start_time, start_time))
    conn.commit()
    conn.close()

    # Time jump of 30 days
    t_jump = start_time + 30 * 86400
    res = reg_purge.run_registration_purge(current_time=t_jump)
    assert res["clock_guard_tripped"] is True

    # Check database: rows remain PENDING_APPROVAL and approval_purge_tripped is 1
    conn = sqlite3.connect(setup_isolated_env["db"])
    count = conn.execute("SELECT COUNT(*) FROM self_registrations WHERE status = 'PENDING_APPROVAL'").fetchone()[0]
    tripped = conn.execute("SELECT approval_purge_tripped FROM self_registration_settings WHERE id = 1").fetchone()[0]
    conn.close()
    assert count == 12
    assert tripped == 1

    # Force purge endpoint (fulladmin)
    monkeypatch.setattr(time, "time", lambda: t_jump)
    token = _get_admin_token(setup_isolated_env["db"])
    force_resp = client.post(
        "/api/v1/registrations/approval-purge/force",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert force_resp.status_code == 200
    assert force_resp.json()["result"]["expired_approval"] == 12

    # Check database: all 12 are now EXPIRED_APPROVAL
    conn = sqlite3.connect(setup_isolated_env["db"])
    count_expired = conn.execute("SELECT COUNT(*) FROM self_registrations WHERE status = 'EXPIRED_APPROVAL'").fetchone()[0]
    tripped_after = conn.execute("SELECT approval_purge_tripped FROM self_registration_settings WHERE id = 1").fetchone()[0]
    conn.close()
    assert count_expired == 12
    assert tripped_after == 0


def test_invariant_7_approve_and_reject_clear_password_enc(setup_isolated_env, monkeypatch):
    """Invariant 7: Approve and Reject both set password_enc = NULL."""
    client = TestClient(app)
    token = _get_admin_token(setup_isolated_env["db"])

    # Mock AD provisioning to avoid system samba calls
    monkeypatch.setattr(samba_svc, "provision_user_in_ad", lambda *args, **kwargs: (True, "User created successfully"))
    monkeypatch.setattr(reg_mod, "provision_user_in_ad", lambda *args, **kwargs: (True, "User created successfully"))

    # 1. Create and verify user 1 -> PENDING_APPROVAL -> Approve
    r1 = client.post("/api/v1/self-registration/submit", json={
        "username": "user_appr",
        "given_name": "User",
        "surname": "Appr",
        "email": "user_appr@example.com",
        "mobile": "+1234567891",
        "password": "Password123!",
        "department": "Engineering"
    })
    reg1_id = r1.json()["registration_id"]
    otp1 = CAPTURED_OTPS["+1234567891"]
    v1 = client.post("/api/v1/self-registration/verify-otp", json={"registration_id": reg1_id, "otp_code": otp1})
    assert v1.status_code == 200

    appr_resp = client.post(
        f"/api/v1/registrations/requests/{reg1_id}/approve",
        json={"notes": "Approved for testing"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert appr_resp.status_code == 200

    conn = sqlite3.connect(setup_isolated_env["db"])
    row_appr = conn.execute("SELECT status, password_enc FROM self_registrations WHERE id = ?", (reg1_id,)).fetchone()
    conn.close()
    assert row_appr[0] == "APPROVED"
    assert row_appr[1] is None

    # 2. Create and verify user 2 -> PENDING_APPROVAL -> Reject
    r2 = client.post("/api/v1/self-registration/submit", json={
        "username": "user_rej",
        "given_name": "User",
        "surname": "Rej",
        "email": "user_rej@example.com",
        "mobile": "+1234567892",
        "password": "Password123!",
        "department": "Engineering"
    })
    reg2_id = r2.json()["registration_id"]
    otp2 = CAPTURED_OTPS["+1234567892"]
    v2 = client.post("/api/v1/self-registration/verify-otp", json={"registration_id": reg2_id, "otp_code": otp2})
    assert v2.status_code == 200

    rej_resp = client.post(
        f"/api/v1/registrations/requests/{reg2_id}/reject",
        json={"notes": "Rejected for testing"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert rej_resp.status_code == 200

    conn = sqlite3.connect(setup_isolated_env["db"])
    row_rej = conn.execute("SELECT status, password_enc FROM self_registrations WHERE id = ?", (reg2_id,)).fetchone()
    conn.close()
    assert row_rej[0] == "REJECTED"
    assert row_rej[1] is None


def test_invariant_8_key_rotation(setup_isolated_env):
    """Invariant 8: Ciphertext encrypted with k1 still decrypts after k2 becomes the newest key."""
    # Ensure key 1 is generated and encrypt plaintext
    pw_plain = "SuperSecretRotationPw!"
    ct1 = secret_box.encrypt_registration_password(100, "user_rot", pw_plain)
    k1_id = ct1.split(":")[1]

    # Rotate by creating key 2
    time.sleep(0.01)
    k2_id, _ = secret_box.create_new_key()
    assert k2_id != k1_id

    # Newest key must now be k2
    latest_id, _ = secret_box.get_newest_key()
    assert latest_id == k2_id

    # But ct1 encrypted under k1 must still decrypt cleanly
    decrypted = secret_box.decrypt_registration_password(100, "user_rot", ct1)
    assert decrypted == pw_plain


def test_invariant_9_tampered_ciphertext_sets_error_reregister(setup_isolated_env, monkeypatch):
    """Invariant 9: Tampered ciphertext sets status = ERROR_REREGISTER and logs audit event."""
    client = TestClient(app)
    token = _get_admin_token(setup_isolated_env["db"])

    resp = client.post("/api/v1/self-registration/submit", json={
        "username": "user_tamper",
        "given_name": "User",
        "surname": "Tamper",
        "email": "user_tamper@example.com",
        "mobile": "+1234567893",
        "password": "Password123!",
        "department": "Engineering"
    })
    reg_id = resp.json()["registration_id"]
    otp = CAPTURED_OTPS["+1234567893"]
    client.post("/api/v1/self-registration/verify-otp", json={"registration_id": reg_id, "otp_code": otp})

    # Tamper with the ciphertext in database
    conn = sqlite3.connect(setup_isolated_env["db"])
    cursor = conn.cursor()
    cursor.execute("SELECT password_enc FROM self_registrations WHERE id = ?", (reg_id,))
    orig_ct = cursor.fetchone()[0]
    parts = orig_ct.split(":")
    # Alter payload
    tampered_ct = f"{parts[0]}:{parts[1]}:dGFtcGVyZWRAYXRhbnU="
    cursor.execute("UPDATE self_registrations SET password_enc = ? WHERE id = ?", (tampered_ct, reg_id))
    conn.commit()
    conn.close()

    # Admin approval attempt must fail and status set to ERROR_REREGISTER
    appr_resp = client.post(
        f"/api/v1/registrations/requests/{reg_id}/approve",
        json={},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert appr_resp.status_code == 400
    assert "decryption failed" in appr_resp.json()["detail"].lower()

    conn = sqlite3.connect(setup_isolated_env["db"])
    status = conn.execute("SELECT status, password_enc FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()
    # Check audit event
    audit_row = conn.execute("SELECT event_type, status FROM audit_events WHERE (target = 'user_tamper' OR actor = 'user_tamper') AND event_type = 'REGISTRATION_DECRYPT_FAILED'").fetchone()
    conn.close()

    assert status[0] == "ERROR_REREGISTER"
    assert status[1] is None
    assert audit_row is not None
    assert audit_row[1] == "ERROR"


def test_invariant_10_password_never_in_run_cmd_argv(monkeypatch):
    """Invariant 10: Password never appears in run_cmd arguments during AD account provisioning."""
    captured_cmds = []
    captured_inputs = []

    def mock_run_cmd(cmd, timeout=30, input_data=None):
        captured_cmds.append(cmd)
        captured_inputs.append(input_data)
        return (0, "User created successfully", "")

    monkeypatch.setattr(samba_svc, "run_cmd", mock_run_cmd)

    test_pw = "VeryConfidentialADPassword2026!"
    ok = samba_svc.provision_user_in_ad(
        username="ad_user_inv10",
        password=test_pw,
        given_name="AD",
        surname="User",
        email="ad_user10@example.com",
        mobile="+1234567890",
        department="Engineering"
    )
    assert ok is True

    # Invariant: test_pw must not be in any cmd element
    for cmd in captured_cmds:
        cmd_str = " ".join(cmd)
        assert test_pw not in cmd_str, f"Password leaked in argv: {cmd_str}"

    # Verify test_pw was passed cleanly via input_data stdin
    assert any(captured_input and test_pw in captured_input for captured_input in captured_inputs)


def test_invariant_11_takeover_prevention(setup_isolated_env):
    """Invariant 11: Different mobile for pending user returns 409; PENDING_APPROVAL row untouched."""
    client = TestClient(app)

    # 1. First submission by legitimate user
    r1 = client.post("/api/v1/self-registration/submit", json={
        "username": "victim_user",
        "given_name": "Victim",
        "surname": "Person",
        "email": "victim@example.com",
        "mobile": "+1234567890",
        "password": "Password123!",
        "department": "Engineering"
    })
    assert r1.status_code == 200
    reg_id = r1.json()["registration_id"]

    # 2. Attacker attempts to take over with same username but different mobile -> 409
    r2 = client.post("/api/v1/self-registration/submit", json={
        "username": "victim_user",
        "given_name": "Attacker",
        "surname": "Person",
        "email": "attacker@example.com",
        "mobile": "+9999999999",
        "password": "EvilPassword123!",
        "department": "Engineering"
    })
    assert r2.status_code == 409
    assert "already in progress" in r2.json()["detail"].lower()

    # 3. Legitimate user verifies OTP to move to PENDING_APPROVAL
    otp = CAPTURED_OTPS["+1234567890"]
    v_resp = client.post("/api/v1/self-registration/verify-otp", json={"registration_id": reg_id, "otp_code": otp})
    assert v_resp.status_code == 200

    # 4. Attacker attempts to resubmit even with same mobile once in PENDING_APPROVAL -> 409
    r3 = client.post("/api/v1/self-registration/submit", json={
        "username": "victim_user",
        "given_name": "Victim",
        "surname": "Person",
        "email": "victim@example.com",
        "mobile": "+1234567890",
        "password": "NewPassword123!",
        "department": "Engineering"
    })
    assert r3.status_code == 409
    assert "already in progress" in r3.json()["detail"].lower()

    # Confirm PENDING_APPROVAL row is intact
    conn = sqlite3.connect(setup_isolated_env["db"])
    row = conn.execute("SELECT status FROM self_registrations WHERE id = ?", (reg_id,)).fetchone()
    conn.close()
    assert row[0] == "PENDING_APPROVAL"


def test_invariant_12_backup_passphrase_roundtrip_and_missing_keys_warning(setup_isolated_env, monkeypatch):
    """Invariant 12: Backup round-trip with passphrase restores keys; wrong passphrase returns 400."""
    import api.routers.system as sys_router

    # Create dummy key in registration_keys
    k_id, k_bytes = secret_box.create_new_key()
    assert (setup_isolated_env["conf"] / "registration_keys" / k_id).exists()

    # Insert a pending request encrypted with k_id
    conn = sqlite3.connect(setup_isolated_env["db"])
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO self_registrations (
            username, email, given_name, surname, mobile, status, created_at, password_enc
        ) VALUES ('pending_bk', 'pbk@example.com', 'Pending', 'BK', '+111', 'PENDING_APPROVAL', ?, ?)
    """, (time.time(), f"v1:{k_id}:dummycipher"))
    conn.commit()
    conn.close()

    # 1. Create encrypted backup
    create_req = sys_router.BackupCreateRequest(
        backup_type="config_only",
        description="Encrypted test backup",
        passphrase="AdminSecretPassphrase2026!"
    )
    b_resp = sys_router.create_backup(create_req)
    assert b_resp["status"] == "success"
    assert b_resp["is_encrypted"] is True
    archive_name = b_resp["filename"]

    # 2. Inspect with wrong passphrase -> HTTP 400
    with pytest.raises(Exception) as excinfo:
        sys_router.inspect_backup(sys_router.BackupInspectRequest(
            filename=archive_name,
            passphrase="WrongPassword!"
        ))
    assert excinfo.value.status_code == 400

    # 3. Inspect with correct passphrase -> Success
    insp = sys_router.inspect_backup(sys_router.BackupInspectRequest(
        filename=archive_name,
        passphrase="AdminSecretPassphrase2026!"
    ))
    assert insp["status"] == "success"
    assert insp["is_encrypted"] is True

    # 4. Wipe keys locally to test restoration
    shutil.rmtree(setup_isolated_env["conf"] / "registration_keys")
    assert not (setup_isolated_env["conf"] / "registration_keys").exists()

    # Restore with correct passphrase
    rest_resp = sys_router.restore_backup(sys_router.BackupRestoreRequest(
        filename=archive_name,
        passphrase="AdminSecretPassphrase2026!"
    ))
    assert rest_resp["status"] == "success"
    # Registration key was restored!
    restored_key_file = setup_isolated_env["conf"] / "registration_keys" / k_id
    assert restored_key_file.exists()
    assert restored_key_file.read_bytes() == k_bytes

    # 5. Test missing key warning banner if a row references a deleted key
    restored_key_file.unlink()
    missing_count = secret_box.check_missing_registration_keys()
    assert missing_count == 1


def test_invariant_13_unencrypted_backup_contains_no_registration_keys(setup_isolated_env):
    """Invariant 13: An unencrypted backup leaves registration_keys/ out of archive and sets registration_keys_included: false."""
    import tarfile
    import api.routers.system as sys_router

    # Ensure at least one key exists
    k_id, _ = secret_box.create_new_key()
    assert (setup_isolated_env["conf"] / "registration_keys" / k_id).exists()

    # Create unencrypted backup
    create_req = sys_router.BackupCreateRequest(
        backup_type="config_only",
        description="Unencrypted backup",
        passphrase=None
    )
    b_resp = sys_router.create_backup(create_req)
    assert b_resp["status"] == "success"
    assert b_resp["is_encrypted"] is False
    assert b_resp["manifest"]["registration_keys_included"] is False

    archive_path = setup_isolated_env["data"] / "backups" / b_resp["filename"]
    assert archive_path.exists()

    with tarfile.open(archive_path, "r:gz") as tar:
        names = tar.getnames()
        for name in names:
            assert "registration_keys" not in name, f"Found registration_keys entry in unencrypted backup: {name}"
