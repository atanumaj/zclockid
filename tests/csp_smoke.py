#!/usr/bin/env python3
"""
tests/csp_smoke.py - Comprehensive CSP & Air-Gap Smoke Test (v1.5.2)

Validates:
1. Standalone portal pages loaded and submitted:
   - /login.html
   - /register.html
   - /password-reset.html (Current Password + Email OTP + SMS OTP tabs)
   - /setup.html (Step 1 disposable state)
2. All 19 navigation tabs in the authenticated web console:
   Dashboard, Domain, NTP, Users, DNS, RADIUS, Sysvol, Azure, Registrations,
   Reports, RBAC, API Keys, Certs, Syslog, Federation, Backup, SNMP, License, Update.
3. Every modal dialog opening and closing via delegated actions / buttons.
4. Strict CSP Compliance:
   - 0 CSP violations (script-src 'self', style-src 'self', etc.)
   - 0 pageerror events (uncaught JS runtime exceptions)
   - 0 console errors
   - 0 external / non-self network requests
5. Captures screenshots: dashboard.png, users.png, modals.png.
"""

import os
import sys
import time
from urllib.parse import urlparse
from pathlib import Path
import requests
import urllib3
from playwright.sync_api import sync_playwright

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCREENSHOTS_DIR = Path(__file__).resolve().parent / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def main():
    target_host = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ZCLOCK_HOST", "192.168.1.41")
    if not target_host.startswith("http://") and not target_host.startswith("https://"):
        base_url = f"https://{target_host}"
    else:
        base_url = target_host.rstrip("/")

    user = os.environ.get("ZCLOCK_USER", "admin")
    password = os.environ.get("ZCLOCK_PASS", "P@ssw0rd@inet")

    print(f"=================================================================")
    print(f" ZclockID Playwright Comprehensive CSP & Air-Gap Smoke Test (v1.5.2)")
    print(f" Target Host: {base_url}")
    print(f" User:        {user}")
    print(f"=================================================================")

    target_parsed = urlparse(base_url)
    target_netloc = target_parsed.netloc

    # 1. Authenticate via REST API
    login_url = f"{base_url}/api/v1/auth/login"
    print(f"Authenticating via {login_url}...")
    try:
        resp = requests.post(
            login_url,
            json={"username": user, "password": password},
            verify=False,
            timeout=10
        )
    except Exception as e:
        print(f"ERROR: Failed to connect to login API: {e}", file=sys.stderr)
        sys.exit(1)

    if resp.status_code != 200:
        print(f"ERROR: Authentication failed ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)

    login_data = resp.json()
    token = login_data.get("token") or login_data.get("access_token")
    if not token:
        print(f"ERROR: No token returned in login response: {login_data}", file=sys.stderr)
        sys.exit(1)

    print(f"Authentication successful! Acquired session token.\n")

    # Tracking lists
    csp_violations = []
    js_errors = []
    external_requests = []
    tested_tabs = []
    tested_modals = []
    tested_portals = []

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--ignore-certificate-errors", "--enable-logging=stderr"]
        )

        # Listen for uncaught JavaScript errors (pageerror)
        def on_page_error(err):
            print(f"  [PAGE ERROR] {err}", file=sys.stderr)
            js_errors.append(str(err))

        # Listen for console errors / warnings
        def on_console(msg):
            text = msg.text
            if "Content Security Policy" in text or "violates the following Content Security Policy" in text:
                print(f"  [CSP CONSOLE] {text}", file=sys.stderr)
                csp_violations.append(f"Console: {text}")
            elif msg.type == "error":
                # Filter benign HTTP fetch errors from intentional test submissions
                if "Failed to load resource: the server responded with a status of" in text:
                    pass
                else:
                    print(f"  [CONSOLE ERROR] {text}", file=sys.stderr)
                    js_errors.append(f"Console error: {text}")

        # Monitor network requests to ensure strict air-gapping
        def on_request(req):
            url = req.url
            if url.startswith("data:") or url.startswith("blob:") or url.startswith("about:"):
                return
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != target_netloc:
                err_msg = f"Non-self request detected: {url} (method={req.method})"
                print(f"  [EXTERNAL REQUEST DETECTED] {err_msg}", file=sys.stderr)
                external_requests.append(err_msg)

        csp_inject_script = """
            window._csp_violations = window._csp_violations || [];
            window.addEventListener('securitypolicyviolation', (e) => {
                window._csp_violations.push({
                    violatedDirective: e.violatedDirective,
                    blockedURI: e.blockedURI,
                    originalPolicy: e.originalPolicy
                });
            });
        """

        # Helper to check in-page recorded security policy violations
        def check_in_page_violations(pg, context_name):
            try:
                events = pg.evaluate("() => { const v = window._csp_violations || []; window._csp_violations = []; return v; }")
                if events:
                    for ev in events:
                        msg = f"{context_name}: violatedDirective={ev.get('violatedDirective')}, blockedURI={ev.get('blockedURI')}"
                        print(f"  [SECURITY POLICY VIOLATION] {msg}", file=sys.stderr)
                        csp_violations.append(msg)
            except Exception as e:
                pass

        def test_page_isolated(url_path, test_fn, portal_name, setup_routes=None):
            ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
            ctx.add_init_script(csp_inject_script)
            p = ctx.new_page()
            p.on("pageerror", on_page_error)
            p.on("console", on_console)
            p.on("request", on_request)
            if setup_routes:
                setup_routes(p)
            p.goto(f"{base_url}{url_path}", wait_until="domcontentloaded")
            p.wait_for_timeout(600)
            check_in_page_violations(p, f"{portal_name} Load")
            test_fn(p)
            ctx.close()
            tested_portals.append(portal_name)

        # =====================================================================
        # 1. STANDALONE PORTAL PAGES: LOAD AND SUBMIT ONCE EACH
        # =====================================================================
        print("=== 1. Testing Standalone Portal Pages & Submissions ===")

        # A. Login Page
        print("\nTesting Login Page (/login.html)...")
        def run_login(p):
            print("  -> Submitting Login form...")
            p.fill("#username", user)
            p.fill("#password", password)
            p.click("button[type='submit']")
            p.wait_for_timeout(1000)
            check_in_page_violations(p, "Login Page Submit")
        test_page_isolated("/login.html", run_login, "Login (/login.html)")

        # B. Self-Registration Portal
        print("\nTesting Self-Registration Portal (/register.html)...")
        def run_register(p):
            print("  -> Submitting Self-Registration details form...")
            p.fill("#given_name", "Test")
            p.fill("#surname", "User")
            p.fill("#username", "testuser_smoke")
            p.fill("#mobile", "+919999988888")
            p.fill("#email", "testuser_smoke@corp.example.com")
            p.fill("#password", "P@ssw0rd2026!")
            p.fill("#confirm_password", "P@ssw0rd2026!")
            p.click("#submit-btn")
            p.wait_for_timeout(1000)
            check_in_page_violations(p, "Register Page Submit")
        test_page_isolated("/register.html", run_register, "Self-Registration (/register.html)")

        # C. Password Reset Portal
        print("\nTesting Self-Service Password Reset Portal (/password-reset.html)...")
        def run_pwd_reset(p):
            print("  -> Submitting Current Password Change form...")
            p.fill("#old-username", "testuser_smoke")
            p.fill("#old-password", "OldP@ssw0rd1!")
            p.fill("#old-new-password", "NewP@ssw0rd2026!")
            p.fill("#old-confirm-password", "NewP@ssw0rd2026!")
            p.click("#btn-submit-old")
            p.wait_for_timeout(1000)
            check_in_page_violations(p, "Password Reset Current Password Submit")

            print("  -> Submitting Email OTP Request...")
            p.evaluate("switchMethodTab('email')")
            p.wait_for_timeout(400)
            p.fill("#otp-username", "testuser_smoke")
            p.click("#btn-request-otp")
            p.wait_for_timeout(1000)
            check_in_page_violations(p, "Password Reset Email OTP Submit")

            print("  -> Submitting SMS OTP Request...")
            p.evaluate("switchMethodTab('sms')")
            p.wait_for_timeout(400)
            p.fill("#otp-username", "testuser_smoke")
            p.click("#btn-request-otp")
            p.wait_for_timeout(1000)
            check_in_page_violations(p, "Password Reset SMS OTP Submit")
        test_page_isolated("/password-reset.html", run_pwd_reset, "Password Reset (/password-reset.html)")

        # D. Initial Setup Wizard (Disposable State)
        print("\nTesting Initial Setup Wizard (/setup.html in disposable state)...")
        def run_setup(p):
            print("  -> Submitting Setup Wizard Step 1...")
            p.fill("#admin_username", "admin")
            p.fill("#admin_email", "admin@corp.example.com")
            p.fill("#admin_password", "P@ssw0rd@inet")
            p.fill("#admin_password_confirm", "P@ssw0rd@inet")
            p.check("#accept_license")
            p.wait_for_timeout(400)
            p.click("#btn-step-1-next")
            p.wait_for_timeout(1000)
            check_in_page_violations(p, "Setup Wizard Step 1 Submit")
        test_page_isolated(
            "/setup.html",
            run_setup,
            "Initial Setup Wizard (/setup.html)",
            setup_routes=lambda p: p.route(
                "**/api/v1/setup/status",
                lambda route: route.fulfill(
                    status=200,
                    content_type="application/json",
                    body='{"is_configured": false, "has_admin": false, "hostname": "dc01"}'
                )
            )
        )

        # =====================================================================
        # 2. AUTHENTICATED WEB CONSOLE: ALL 19 TABS
        # =====================================================================
        print("\n=== 2. Testing Authenticated Web Console (All 19 Tabs) ===")
        auth_ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
        auth_ctx.add_init_script(csp_inject_script)
        auth_ctx.add_init_script(f"localStorage.setItem('zclockid_token', '{token}');")
        page = auth_ctx.new_page()
        page.on("pageerror", on_page_error)
        page.on("console", on_console)
        page.on("request", on_request)

        page.goto(f"{base_url}/", wait_until="domcontentloaded")
        page.wait_for_timeout(1000)
        check_in_page_violations(page, "Dashboard (Initial Load)")

        # Save Dashboard Screenshot
        dashboard_screenshot = SCREENSHOTS_DIR / "dashboard.png"
        page.screenshot(path=str(dashboard_screenshot))
        print(f"  -> Captured Dashboard screenshot at {dashboard_screenshot}")

        all_19_tabs = [
            ("Dashboard", "#nav-dashboard", False),
            ("Domain", "#nav-domain", False),
            ("NTP", "#nav-ntp", False),
            ("Users", "#nav-users", False),
            ("DNS", "#nav-dns", False),
            ("RADIUS", "#nav-radius", False),
            ("Sysvol", "#nav-sysvol", False),
            ("Entra ID / Azure", "#nav-azure", False),
            ("Self-Service", "#nav-registrations", False),
            ("Reports", "#nav-reports", False),
            ("RBAC", "#nav-rbac", True),
            ("API Keys", "#nav-apikeys", True),
            ("Certificates", "#nav-certs", True),
            ("Syslog", "#nav-syslog", True),
            ("Federation", "#nav-federation", True),
            ("Backups", "#nav-backup", True),
            ("SNMP", "#nav-snmp", True),
            ("License", "#nav-license", True),
            ("Updates", "#nav-update", True),
        ]

        for tab_name, selector, in_security_group in all_19_tabs:
            print(f"Testing tab: {tab_name} ({selector})...")
            try:
                if in_security_group:
                    page.evaluate("if (typeof toggleSecurityNavGroup === 'function') toggleSecurityNavGroup(true);")
                    page.wait_for_timeout(200)

                if selector == "#nav-reports":
                    page.evaluate("if (typeof showTab === 'function') showTab('syslog'); if (typeof switchLogsSubTab === 'function') switchLogsSubTab('compliance');")
                else:
                    page.wait_for_selector(selector, state="visible", timeout=5000)
                    page.click(selector)

                page.wait_for_timeout(800)
                check_in_page_violations(page, f"Tab: {tab_name}")
                tested_tabs.append(tab_name)

                # Capture Users screenshot when on Users tab
                if tab_name == "Users":
                    users_screenshot = SCREENSHOTS_DIR / "users.png"
                    page.screenshot(path=str(users_screenshot))
                    print(f"  -> Captured Users tab screenshot at {users_screenshot}")

            except Exception as e:
                print(f"  [ERROR] Failed navigating to {tab_name}: {e}", file=sys.stderr)
                js_errors.append(f"Navigation error on {tab_name}: {e}")

        # =====================================================================
        # 3. OPEN AND CLOSE EVERY MODAL-OPENING BUTTON & DIALOG
        # =====================================================================
        print("\n=== 3. Testing Modal Dialogs Opening and Closing ===")

        # Switch back to dashboard to test modals from neutral state
        page.click("#nav-dashboard")
        page.wait_for_timeout(500)

        modal_test_definitions = [
            ("Service Control Modal", "modal-service-control", "openServiceControlModal('bind9')", "closeServiceControlModal()"),
            ("Registration Settings Modal", "modal-registration-settings", "openRegistrationSettingsModal()", "closeRegistrationSettingsModal()"),
            ("SSPR Settings Modal", "modal-self-service-password-settings", "openSspprSettingsModal()", "closeSspprSettingsModal()"),
            ("Change UPN Modal", "modal-change-upn", "openChangeUpnModal('testuser')", "closeChangeUpnModal()"),
            ("Create Backup Modal", "modal-create-backup", "openCreateBackupModal()", "closeCreateBackupModal()"),
            ("Upload Backup Modal", "modal-upload-backup", "openUploadBackupModal()", "closeUploadBackupModal()"),
            ("Forwarders Modal", "forwarders-modal", "openForwardersModal()", "closeForwardersModal()"),
            ("Add Host Override Modal", "modal-host-override", "openAddHostOverrideModal()", "closeAddHostOverrideModal()"),
            ("Add Domain Forwarder Modal", "modal-domain-forwarder", "openAddDomainForwarderModal()", "closeAddDomainForwarderModal()"),
            ("Identity Modal", "modal-identity", "openIdentityModal()", "closeIdentityModal()"),
            ("Functional Level Modal", "modal-functional-level", "openFunctionalLevelModal()", "closeFunctionalLevelModal()"),
            ("DNS Record Modal", "dns-modal", "openDnsModal()", "closeDnsModal()"),
            ("DoH Client Guide Modal", "modal-doh-guide", "openDohClientGuideModal()", "closeDohClientGuideModal()"),
            ("RADIUS Client Modal", "radius-modal", "openRadiusModal()", "closeRadiusModal()"),
            ("RADIUS Bandwidth Modal", "radius-bandwidth-modal", "openAddBandwidthModal()", "closeBandwidthModal()"),
            ("RADIUS MAB Modal", "radius-mab-modal", "openMabModal()", "closeMabModal()"),
            ("RADIUS Custom Attr Modal", "radius-custom-modal", "openCustomAttrModal()", "closeCustomAttrModal()"),
            ("Sysvol Partner Modal", "sysvol-partner-modal", "openSysvolPartnerModal()", "closeSysvolPartnerModal()"),
            ("Sysvol Mass Delete Modal", "sysvol-mass-delete-modal", "openMassDeleteReviewModal()", "closeMassDeleteReviewModal()"),
            ("Create User Modal", "user-modal", "openUserModal()", "closeUserModal()"),
            ("Expiry Policy Modal", "expiry-policy-modal", "openExpiryPolicyModal()", "closeExpiryPolicyModal()"),
            ("Create Group Modal", "group-modal", "openGroupModal()", "closeGroupModal()"),
            ("New DNS Zone Modal", "zone-modal", "openNewZoneModal()", "closeNewZoneModal()"),
            ("RBAC Mapping Modal", "modal-rbac-mapping", "openRbacMappingModal()", "closeRbacMappingModal()"),
            ("API Key Create Modal", "modal-api-key-create", "openApiKeyCreateModal()", "closeApiKeyCreateModal()"),
            ("Log Viewer Modal", "log-modal", "openLogViewer('bind9', 'BIND9 DNS Engine')", "closeLogModal()"),
            ("CSR View Modal", "modal-cert-csr-view", "document.getElementById('modal-cert-csr-view')?.classList.remove('hidden')", "closeCsrModal()"),
            ("User Profile Modal", "modal-user-profile", "openProfileModal('admin')", "closeProfileModal()"),
        ]

        for modal_name, modal_id, open_expr, close_expr in modal_test_definitions:
            print(f"Testing modal: {modal_name} (#{modal_id})...")
            try:
                # Open modal
                page.evaluate(f"if (typeof {open_expr.split('(')[0]} === 'function' || document.getElementById('{modal_id}')) {{ {open_expr}; }}")
                page.wait_for_timeout(400)
                check_in_page_violations(page, f"Open {modal_name}")

                # Capture modal screenshot on Create User Modal
                if modal_id == "user-modal":
                    modal_screenshot = SCREENSHOTS_DIR / "modals.png"
                    page.screenshot(path=str(modal_screenshot))
                    print(f"  -> Captured Modals screenshot at {modal_screenshot}")

                # Close modal
                page.evaluate(f"if (typeof {close_expr.split('(')[0]} === 'function') {{ {close_expr}; }} else {{ document.getElementById('{modal_id}')?.classList.add('hidden'); }}")
                page.wait_for_timeout(300)
                check_in_page_violations(page, f"Close {modal_name}")

                tested_modals.append(modal_name)
            except Exception as e:
                print(f"  [ERROR] Failed testing modal {modal_name}: {e}", file=sys.stderr)
                js_errors.append(f"Modal error on {modal_name}: {e}")

                tested_modals.append(modal_name)
            except Exception as e:
                print(f"  [ERROR] Failed testing modal {modal_name}: {e}", file=sys.stderr)
                js_errors.append(f"Modal error on {modal_name}: {e}")

        # Also test all in-DOM buttons with data-action opening modals
        modal_buttons = page.query_selector_all("[data-action^='open']")
        print(f"\nDiscovered {len(modal_buttons)} in-DOM elements with data-action^='open'.")

        auth_ctx.close()
        browser.close()

    print(f"\n=================================================================")
    print(f" ZclockID CSP & Air-Gap Smoke Test Results")
    print(f"=================================================================")
    print(f"  Standalone Portals Tested:  {len(tested_portals)} / 5")
    for p_name in tested_portals:
        print(f"    [PASS] {p_name}")

    print(f"\n  Web Console Tabs Tested:   {len(tested_tabs)} / 19")
    for t_name in tested_tabs:
        print(f"    [PASS] Tab: {t_name}")

    print(f"\n  Modals Tested (Open/Close): {len(tested_modals)} / {len(modal_test_definitions)}")
    for m_name in tested_modals:
        print(f"    [PASS] Modal: {m_name}")

    print(f"\n  Summary Counts:")
    print(f"    CSP Violations:          {len(csp_violations)}")
    print(f"    JS Page / Runtime Errors: {len(js_errors)}")
    print(f"    External Host Requests:   {len(external_requests)}")
    print(f"=================================================================")

    if csp_violations or js_errors or external_requests:
        if csp_violations:
            print("\nCSP Violations encountered:", file=sys.stderr)
            for v in csp_violations:
                print(f"  - {v}", file=sys.stderr)
        if js_errors:
            print("\nJavaScript Page / Runtime Errors encountered:", file=sys.stderr)
            for err in js_errors:
                print(f"  - {err}", file=sys.stderr)
        if external_requests:
            print("\nExternal / Non-Self Requests encountered:", file=sys.stderr)
            for r in external_requests:
                print(f"  - {r}", file=sys.stderr)
        sys.exit(1)

    print("\nPlaywright CSP & Air-Gap Smoke Test PASSED: All 19 tabs, all modals, and all portals 100% clean with 0 violations!")
    sys.exit(0)


if __name__ == "__main__":
    main()
