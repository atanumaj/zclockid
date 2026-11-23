#!/usr/bin/env python3
"""
ZclockID v1.5.3.1 - Stored-XSS Playwright Verification Test
===========================================================
Submits a self-registration with `<img src=x onerror=alert(1)>` and `"><svg onload=alert(1)>`
in every free-text field.
Renders the admin Registrations tab and the user detail modal in Playwright Chromium.
Asserts that no alert/confirm dialogs fire and that the payload strings appear literally in the DOM.
"""

import os
import sys
import time
import json
import secrets
import urllib3
import requests
import pytest

# Ensure Playwright is available; skip collection if not installed
playwright = pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not os.environ.get("ZCLOCK_HOST") or not os.environ.get("ZCLOCK_PASS"),
        reason="Live VM test requires ZCLOCK_HOST and ZCLOCK_PASS environment variables"
    )
]


def test_stored_xss_registrations_and_user_modal():
    target_host = os.environ.get("ZCLOCK_HOST")
    admin_user = os.environ.get("ZCLOCK_USER", "admin")
    admin_pass = os.environ.get("ZCLOCK_PASS")

    if not target_host or not admin_pass:
        pytest.skip("ZCLOCK_HOST and ZCLOCK_PASS environment variables must be set")

    if not target_host.startswith("http://") and not target_host.startswith("https://"):
        base_url = f"https://{target_host}"
    else:
        base_url = target_host.rstrip("/")

    print(f"\n=== ZclockID Stored-XSS Verification Test (v1.5.3.1) ===")
    print(f"Target: {base_url}")

    # 1. Authenticate to obtain admin token
    session = requests.Session()
    session.verify = False
    login_resp = session.post(f"{base_url}/api/v1/auth/login", json={
        "username": admin_user,
        "password": admin_pass
    }, timeout=10)
    assert login_resp.status_code == 200, f"Login failed: {login_resp.status_code} {login_resp.text}"
    token = login_resp.json().get("access_token")
    assert token, "No access token in login response"
    print("  [+] Authenticated as admin successfully.")

    # 2. Submit self-registration containing XSS payloads in every free-text field
    rand_suffix = secrets.token_hex(4)
    xss_username = f"xss_{rand_suffix}"
    payload_img = "<img src=x onerror=alert(1)>"
    payload_svg = '"><svg onload=alert(1)>'

    reg_payload = {
        "username": xss_username,
        "password": "XssP@ssw0rd2026!",
        "given_name": payload_img,
        "surname": payload_svg,
        "email": f"xss_{rand_suffix}@example.com",
        "mobile": f"+9198{secrets.randbelow(90000000) + 10000000}",
        "department": payload_img,
        "job_title": payload_svg,
        "justification": f"{payload_img} {payload_svg}"
    }

    print(f"  [+] Submitting self-registration for '{xss_username}' with XSS payloads...")
    reg_resp = session.post(f"{base_url}/api/v1/self-registration/submit", json=reg_payload, timeout=10)
    assert reg_resp.status_code in (200, 201), f"Registration submit failed: {reg_resp.status_code} {reg_resp.text}"
    print(f"  [+] Registration submitted. Status: {reg_resp.json().get('status')}")

    # 3. Launch Playwright and verify Registrations Tab and User Detail Modal
    print("  [+] Launching Playwright Chromium...")
    dialogs_fired = []
    page_errors = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # Listen for any alert, confirm, or prompt dialogs
        page.on("dialog", lambda d: (
            dialogs_fired.append({"message": d.message, "type": d.type}),
            print(f"  [!] ALERT / DIALOG FIRED: {d.message} (type: {d.type})"),
            d.dismiss()
        ))

        page.on("pageerror", lambda err: (
            page_errors.append(str(err)),
            print(f"  [!] Page error: {err}")
        ))

        # Prime localStorage with session token
        page.goto(f"{base_url}/login.html", wait_until="domcontentloaded")
        page.evaluate(f"""
            localStorage.setItem('zclockid_token', '{token}');
            localStorage.setItem('zclockid_user', '{admin_user}');
            localStorage.setItem('zclockid_role', 'fulladmin');
        """)

        # Navigate to Web Console
        page.goto(f"{base_url}/index.html", wait_until="domcontentloaded")
        page.wait_for_timeout(2000)

        # A. Render admin Registrations tab
        print("  [+] Navigating to Registrations Tab...")
        page.evaluate("showTab('registrations')")
        page.wait_for_timeout(2000)

        reg_table_html = page.inner_html("#registrations-table-body")
        assert payload_img in reg_table_html or "&lt;img" in reg_table_html, "Payload img missing from table"
        assert payload_svg in reg_table_html or "&lt;svg" in reg_table_html, "Payload svg missing from table"
        print("  [+] Registrations table safely rendered payload without executing script.")

        # B. Render User Detail Modal with active users
        print("  [+] Navigating to Users Tab & opening Edit User modal...")
        page.evaluate("showTab('users')")
        page.wait_for_timeout(2000)

        # Mock user record with XSS payload to safely trigger edit modal
        mock_user = {
            "username": f"user_{rand_suffix}",
            "display_name": f"{payload_img} {payload_svg}",
            "given_name": payload_img,
            "surname": payload_svg,
            "email": f"safe_{rand_suffix}@example.com",
            "department": payload_img,
            "mobile": "+919800000000",
            "account_status": "Enabled",
            "groups": ["Domain Users"],
            "password_never_expires": False
        }

        # Intercept /api/v1/users* to return our mock user
        page.route("**/api/v1/users*", lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"users": [mock_user], "total": 1})
        ))

        page.evaluate("async () => await fetchUsers()")
        page.wait_for_timeout(1000)

        # Open Edit User Modal for this user
        page.evaluate(f"openEditUserModal('{mock_user['username']}')")
        page.wait_for_timeout(1000)

        modal_el = page.query_selector("#edit-user-modal")
        assert modal_el, "Edit user modal not found in DOM"
        is_visible = modal_el.is_visible()
        assert is_visible, "Edit user modal was not displayed"

        # Check values in input fields
        first_name_val = page.input_value("#edit-usr-given")
        last_name_val = page.input_value("#edit-usr-sur")
        dept_val = page.input_value("#edit-usr-dept")

        assert first_name_val == payload_img, f"First name mismatch: {first_name_val}"
        assert last_name_val == payload_svg, f"Last name mismatch: {last_name_val}"
        assert dept_val == payload_img, f"Department mismatch: {dept_val}"
        print("  [+] User detail modal populated inputs with literal payloads safely.")

        # Close modal
        page.evaluate("closeEditUserModal()")
        page.wait_for_timeout(500)

        browser.close()

    assert len(dialogs_fired) == 0, f"XSS EXPLOITED! Dialogs fired: {dialogs_fired}"
    assert len(page_errors) == 0, f"Page errors occurred during XSS test: {page_errors}"
    print("  [SUCCESS] 0 dialogs fired, 0 page errors. Stored-XSS defense verified.\n")


if __name__ == "__main__":
    test_stored_xss_registrations_and_user_modal()
