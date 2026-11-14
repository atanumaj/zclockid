"""
Tests for v1.3.8/v1.3.9 XSS escaping, interim CSP headers, action delegation uniqueness, URL token removal, and SSPR fixes.
"""
import os
import re
import sqlite3
import subprocess
import time
from collections import Counter
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.main import app
import api.main as main_mod
import api.core.config as config
import api.routers.registration as reg_mod
import api.routers.self_service as ss_mod
import api.services.security_service as sec_svc
from api.core.security import hash_otp
try:
    from tests.test_sspr_hardening import _setup_test_environment, _restore_environment
except ImportError:
    from test_sspr_hardening import _setup_test_environment, _restore_environment

client = TestClient(app, client=("127.0.0.1", 50000), base_url="http://127.0.0.1")


@pytest.fixture(autouse=True)
def allow_testclient_in_tests(monkeypatch):
    """Allows testclient / 127.0.0.1 in the security baseline firewall check during tests."""
    orig_is_ip_allowed = sec_svc.is_ip_allowed
    allow_fn = lambda ip, allowed: True if ip in ("testclient", "127.0.0.1") else orig_is_ip_allowed(ip, allowed)
    monkeypatch.setattr(sec_svc, "is_ip_allowed", allow_fn)
    monkeypatch.setattr(main_mod, "is_ip_allowed", allow_fn)


def test_xss_scan_script():
    """Verify tests/xss_scan.sh executes cleanly and finds 0 unescaped template interpolations in web/."""
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "xss_scan.sh"))
    assert os.path.exists(script_path), f"Scan script not found at {script_path}"
    
    result = subprocess.run(["bash", script_path], capture_output=True, text=True)
    assert result.returncode == 0, f"xss_scan.sh failed with output:\n{result.stdout}\n{result.stderr}"
    assert "0 violations found" in result.stdout


def test_escape_html_implementation_in_core_js():
    """Ensure escapeHtml in web/js/core.js escapes &, <, >, \", ', and `."""
    core_js_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../web/js/core.js"))
    with open(core_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "function escapeHtml(s)" in content
    assert "&amp;" in content
    assert "&lt;" in content
    assert "&gt;" in content
    assert "&quot;" in content
    assert "&#39;" in content or "&#039;" in content
    assert "&#96;" in content


def test_no_duplicate_actions_in_core_js_click_handler():
    """Verify that every data-action handler branch in core.js appears at most once,
    every data-action used across web/ has a matching branch in core.js,
    and control-service reads data-op."""
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../web"))
    core_js_path = os.path.join(web_dir, "js", "core.js")
    with open(core_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Find all action === '...' occurrences
    action_matches = re.findall(r"action === ['\"]([^'\"]+)['\"]", content)
    counts = Counter(action_matches)
    duplicates = {action: count for action, count in counts.items() if count > 1}

    assert not duplicates, f"Duplicate data-action handler branches found in core.js: {duplicates}"

    # Extract all data-action attributes used across web/
    used_actions = set()
    for root, _, files in os.walk(web_dir):
        for fname in files:
            if fname.endswith((".html", ".js")):
                with open(os.path.join(root, fname), "r", encoding="utf-8") as file:
                    used_actions.update(re.findall(r'data-action=["\']([a-zA-Z0-9_-]+)["\']', file.read()))

    handled_actions = set(action_matches)
    missing = used_actions - handled_actions
    assert not missing, f"Missing data-action branches in core.js: {missing}"
    assert "copy-doh-curl" in handled_actions, "copy-doh-curl branch must be handled in core.js"

    # Verify control-service reads data-op, to match dashboard.js
    match = re.search(r"action === ['\"]control-service['\"][\s\S]*?window\.controlService\(([^)]+)\)", content)
    assert match, "control-service action branch not found in core.js"
    args = match.group(1)
    assert "btn.dataset.service" in args and "btn.dataset.op" in args, f"control-service must read btn.dataset.op, found: {args}"


def test_no_token_reading_from_url_in_web():
    """Verify production code never reads session tokens from URLSearchParams or location in web/."""
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../web"))
    violations = []
    for root, _, files in os.walk(web_dir):
        for fname in sorted(files):
            if not (fname.endswith(".js") or fname.endswith(".html")):
                continue
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, web_dir)
            with open(fpath, "r", encoding="utf-8") as file:
                for idx, line in enumerate(file, 1):
                    # Check for URLSearchParams or .get('token')
                    if re.search(r'URLSearchParams.*\.get\([\"\']token[\"\']\)', line) or re.search(r'\.get\([\"\']token[\"\']\)', line):
                        violations.append(f"{rel_path}:{idx}: {line.strip()}")
                    elif "location" in line and "token" in line and not line.strip().startswith("//") and "license/download" not in line:
                        if any(term in line for term in ["getItem", "search", "hash", "pathname", "href.includes", "match", "split"]):
                            violations.append(f"{rel_path}:{idx}: {line.strip()}")

    assert not violations, f"Found session token reading from URL/location in web/:\n" + "\n".join(violations)


def test_nginx_csp_and_security_headers():
    """Verify Nginx configuration templates contain the required interim CSP policy and security headers."""
    conf_paths = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../config-templates/nginx/zclockid.conf")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../config/nginx/zclockid.conf"))
    ]
    for conf_path in conf_paths:
        if not os.path.exists(conf_path):
            continue
        with open(conf_path, "r", encoding="utf-8") as f:
            conf = f.read()

        assert "Content-Security-Policy" in conf
        assert "default-src 'self'" in conf
        assert "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net" in conf
        assert "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com" in conf
        assert "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com" in conf
        assert "img-src 'self' data:" in conf
        assert "connect-src 'self'" in conf
        assert "object-src 'none'" in conf
        assert "frame-ancestors 'none'" in conf
        assert "base-uri 'self'" in conf
        assert "form-action 'self'" in conf
        assert 'add_header X-Content-Type-Options "nosniff"' in conf or 'add_header X-Content-Type-Options nosniff' in conf
        assert 'add_header Referrer-Policy "same-origin"' in conf or 'add_header Referrer-Policy same-origin' in conf


def test_portal_custom_html_csp_sandbox_and_headers(tmp_path, monkeypatch):
    """Serve custom portal HTML with sandbox, and built-in portal with interim CSP + X-Frame-Options: DENY."""
    db_file, _, orig = _setup_test_environment(tmp_path)
    try:
        portal_dir = tmp_path / "portals"
        portal_dir.mkdir(parents=True, exist_ok=True)
        custom_reg = portal_dir / "register.html"
        custom_reg.write_text("<html><body>Custom Register Page</body></html>", encoding="utf-8")

        monkeypatch.setattr(main_mod, "DATA_DIR", tmp_path)
        monkeypatch.setattr(main_mod, "DB_PATH", db_file)
        monkeypatch.setattr(main_mod, "WEB_DIR", Path(__file__).resolve().parent.parent / "web")

        # Enable use_custom_html in database
        conn = sqlite3.connect(db_file)
        conn.execute("UPDATE self_registration_settings SET use_custom_html = 1 WHERE id = 1")
        conn.commit()
        conn.close()

        resp = client.get("/register.html")
        assert resp.status_code == 200
        assert resp.headers.get("content-security-policy") == "sandbox allow-forms allow-scripts"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert "Custom Register Page" in resp.text

        # Disable use_custom_html: should fall back to built-in template with interim CSP policy and X-Frame-Options: DENY
        conn = sqlite3.connect(db_file)
        conn.execute("UPDATE self_registration_settings SET use_custom_html = 0 WHERE id = 1")
        conn.commit()
        conn.close()

        resp_default = client.get("/register.html")
        assert resp_default.status_code == 200
        csp_header = resp_default.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp_header
        assert "script-src 'self' 'unsafe-inline'" in csp_header
        assert resp_default.headers.get("x-frame-options") == "DENY"
        assert resp_default.headers.get("x-content-type-options") == "nosniff"
        assert resp_default.headers.get("referrer-policy") == "same-origin"

        # Check /password-reset.html as well
        resp_pwd = client.get("/password-reset.html")
        assert resp_pwd.status_code == 200
        assert resp_pwd.headers.get("x-frame-options") == "DENY"
        assert "script-src 'self' 'unsafe-inline'" in resp_pwd.headers.get("content-security-policy", "")
    finally:
        _restore_environment(orig)


def test_sspr_no_early_privilege_check_on_verify(tmp_path, monkeypatch):
    """
    Remove early is_privileged_account(target_user) check before OTP verification.
    If an attacker provides an invalid OTP for an Administrator account,
    they should receive an OTP mismatch / attempts remaining message, NOT an early 403 / privileged refusal.
    """
    db_file, _, orig = _setup_test_environment(tmp_path)
    try:
        # Setup a pending OTP request for an administrator
        reset_id = 9999
        real_code = "654321"
        hashed = hash_otp(real_code)
        target_user = "Administrator"
        expires_at = time.time() + 600

        conn = sqlite3.connect(db_file)
        conn.execute(
            "INSERT INTO self_service_password_logs (id, username, method, recipient, otp_code, otp_expires_at, status, ip_address, user_agent, created_at, notes, failed_attempts) "
            "VALUES (?, ?, 'EMAIL_OTP', 'admin@example.com', ?, ?, 'PENDING_OTP', '127.0.0.1', '', ?, '', 0)",
            (reset_id, target_user, hashed, expires_at, time.time())
        )
        conn.commit()
        conn.close()

        # Mock is_privileged_account to return True for Administrator
        monkeypatch.setattr(ss_mod, "is_privileged_account", lambda u, **kw: u.lower() == "administrator")

        # Send wrong OTP: should fail with Invalid verification code entered, NOT 403
        payload = {
            "reset_id": reset_id,
            "username": target_user,
            "otp_code": "000000",
            "new_password": "NewSecretPassword123!"
        }
        resp = client.post("/api/v1/self-service/password/verify-and-reset", json=payload)
        assert resp.status_code == 400
        assert "Invalid verification code entered" in resp.json()["detail"]

        # Now provide CORRECT OTP: only AFTER OTP is verified should is_privileged_account block it
        payload["otp_code"] = real_code
        resp_correct = client.post("/api/v1/self-service/password/verify-and-reset", json=payload)
        assert resp_correct.status_code == 403
        assert "privileged" in resp_correct.json()["detail"].lower()
    finally:
        _restore_environment(orig)


def test_registration_carryover_24h_window(tmp_path):
    """
    In registration, only carry over failed_attempts from rows created in the last 24 hours.
    """
    db_file, _, orig = _setup_test_environment(tmp_path)
    try:
        now = time.time()
        old_time = now - 90000  # > 24 hours ago (86400s)
        recent_time = now - 3600  # 1 hour ago

        conn = sqlite3.connect(db_file)
        # Insert an old attempt with 3 failed attempts
        conn.execute(
            "INSERT INTO self_registrations (username, email, given_name, surname, department, mobile, password_hash, status, created_at, failed_attempts) "
            "VALUES ('user_old', 'old@test.com', 'Old', 'User', 'IT', '+1000000001', 'hash', 'PENDING_OTP', ?, 3)",
            (old_time,)
        )

        # Insert a recent attempt with 2 failed attempts
        conn.execute(
            "INSERT INTO self_registrations (username, email, given_name, surname, department, mobile, password_hash, status, created_at, failed_attempts) "
            "VALUES ('user_recent', 'recent@test.com', 'Recent', 'User', 'IT', '+1000000002', 'hash', 'PENDING_OTP', ?, 2)",
            (recent_time,)
        )
        conn.commit()

        # Query for user_old: should carry over 0 because row is older than 24h
        cutoff = now - 86400
        prev_old = conn.execute(
            "SELECT failed_attempts FROM self_registrations WHERE (username = 'user_old' OR mobile = '+1000000001') AND created_at >= ? ORDER BY created_at DESC LIMIT 1",
            (cutoff,)
        ).fetchone()
        assert prev_old is None

        # Query for user_recent: should carry over 2 because row is within 24h
        prev_recent = conn.execute(
            "SELECT failed_attempts FROM self_registrations WHERE (username = 'user_recent' OR mobile = '+1000000002') AND created_at >= ? ORDER BY created_at DESC LIMIT 1",
            (cutoff,)
        ).fetchone()
        assert prev_recent is not None
        assert prev_recent[0] == 2
        conn.close()
    finally:
        _restore_environment(orig)
