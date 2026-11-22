#!/usr/bin/env python3
"""
ZclockID v1.5.3 - Stored-XSS Playwright Verification Test
=========================================================
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
from playwright.sync_api import sync_playwright

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.41"
BASE_URL = f"https://{TARGET_HOST}"
ADMIN_USER = os.environ.get("ZCLOCK_USER", "admin")
ADMIN_PASS = os.environ.get("ZCLOCK_PASS", "P@ssw0rd@inet")

def run_stored_xss_test():
    print(f"=== ZclockID Stored-XSS Verification Test (v1.5.3) ===")
    print(f"Target: {BASE_URL}")

    # 1. Authenticate to obtain admin token
    session = requests.Session()
    session.verify = False
    login_resp = session.post(f"{BASE_URL}/api/v1/auth/login", json={
        "username": ADMIN_USER,
        "password": ADMIN_PASS
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
    reg_resp = session.post(f"{BASE_URL}/api/v1/self-registration/submit", json=reg_payload, timeout=10)
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
        page.goto(f"{BASE_URL}/login.html", wait_until="domcontentloaded")
        page.evaluate(f"""
            localStorage.setItem('zclockid_token', '{token}');
            localStorage.setItem('zclockid_user', 'admin');
            localStorage.setItem('zclockid_role', 'fulladmin');
        """)

        # Navigate to Web Console
        page.goto(f"{BASE_URL}/index.html", wait_until="domcontentloaded")
        page.wait_for_timeout(2000)

        # A. Render admin Registrations tab
        print("  [+] Navigating to Registrations Tab...")
        page.click("#nav-registrations")
        page.wait_for_timeout(2500)

        # Wait for table body to populate
        tbody = page.locator("#registrations-table-body")
        tbody_text = tbody.inner_text()

        # Assert no alert dialogs fired during rendering
        assert len(dialogs_fired) == 0, f"XSS Failure: Dialog(s) fired in Registrations tab: {dialogs_fired}"
        print("  [+] Verified: No dialog fired upon rendering Registrations tab.")

        # Assert the payload appears literally
        assert xss_username in tbody_text, f"Username '{xss_username}' not found in registrations table"
        assert payload_img in tbody_text, f"Payload '{payload_img}' not found literally in table"
        assert payload_svg in tbody_text, f"Payload '{payload_svg}' not found literally in table"
        print(f"  [+] Verified: Literal payloads '{payload_img}' and '{payload_svg}' safely rendered as text in table.")

        # B. Render User Detail / Edit User Modal with XSS payloads
        print("  [+] Testing User Detail Modal with XSS payloads...")
        # Route /api/v1/users to include our XSS user so fetchUsers() populates internal state
        context.route("**/api/v1/users*", lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({
                "status": "success",
                "users": [
                    {
                        "username": xss_username,
                        "name": xss_username,
                        "given_name": payload_img,
                        "surname": payload_svg,
                        "email": f"xss_{rand_suffix}@example.com",
                        "mobile": "+919800000000",
                        "department": payload_img,
                        "status": "active",
                        "groups": []
                    }
                ]
            })
        ))

        page.click("#nav-users")
        page.wait_for_timeout(2000)

        # Click the user's name in the table to open the user detail modal
        page.click(f"[data-action='edit-user'][data-username='{xss_username}']")
        page.wait_for_timeout(1000)

        # Verify edit modal is visible and inputs hold exact literal payloads
        modal = page.locator("#edit-user-modal")
        assert not modal.get_attribute("class").count("hidden"), "Edit User Modal should be visible"

        given_val = page.locator("#edit-usr-given").input_value()
        sur_val = page.locator("#edit-usr-sur").input_value()
        dept_val = page.locator("#edit-usr-dept").input_value()

        assert given_val == payload_img, f"Given name value mismatch: got '{given_val}'"
        assert sur_val == payload_svg, f"Surname value mismatch: got '{sur_val}'"
        assert dept_val == payload_img, f"Department value mismatch: got '{dept_val}'"

        # Assert absolutely zero dialogs fired
        assert len(dialogs_fired) == 0, f"XSS Failure: Dialog(s) fired in User Detail Modal: {dialogs_fired}"
        print("  [+] Verified: User detail modal rendered exact literal payloads into inputs with 0 dialogs.")

        # Close modal
        page.evaluate("closeEditUserModal()")
        page.wait_for_timeout(300)

        browser.close()

    print("\n=================================================================")
    print(" Stored-XSS Playwright Verification Result: PASSED")
    print(" - Total Dialogs Fired: 0 (No script execution)")
    print(f" - Payload 1 Verified: '{payload_img}' (rendered literally)")
    print(f" - Payload 2 Verified: '{payload_svg}' (rendered literally)")
    print(" - Registrations Tab: Clean")
    print(" - User Detail Modal: Clean")
    print("=================================================================")

if __name__ == "__main__":
    run_stored_xss_test()
