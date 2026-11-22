#!/usr/bin/env python3
"""
tests/csp_smoke.py - Comprehensive CSP & Air-Gap Smoke Test (v1.5.1)

Validates:
1. All 19 navigation tabs in the authenticated web console.
2. Standalone public pages: /login.html, /register.html, /password-reset.html, /setup.html.
3. 0 CSP violations (Content-Security-Policy).
4. 0 pageerror events (uncaught JavaScript runtime exceptions).
5. 0 requests to external / non-self hosts (guarantees 100% self-hosted assets and strict air-gapping).
6. Captures screenshots of Dashboard, Users tab, and Modals.
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
    print(f" ZclockID Playwright Comprehensive CSP & Air-Gap Smoke Test (v1.5.1)")
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

    print(f"Authentication successful! Acquired session token.")

    # 2. Run Headless Playwright Browser Test
    csp_violations = []
    js_errors = []
    external_requests = []

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--ignore-certificate-errors", "--enable-logging=stderr"]
        )
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1440, "height": 900}
        )
        page = context.new_page()

        # Listen for uncaught JavaScript errors (pageerror)
        def on_page_error(err):
            print(f"  [PAGE ERROR] {err}", file=sys.stderr)
            js_errors.append(str(err))

        page.on("pageerror", on_page_error)

        # Listen for console CSP warnings / errors
        def on_console(msg):
            text = msg.text
            if "Content Security Policy" in text or "violates the following Content Security Policy" in text:
                print(f"  [CSP CONSOLE] {text}", file=sys.stderr)
                csp_violations.append(f"Console: {text}")

        page.on("console", on_console)

        # Monitor network requests to ensure strict self-hosting (no non-self requests)
        def on_request(req):
            url = req.url
            if url.startswith("data:") or url.startswith("blob:") or url.startswith("about:"):
                return
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != target_netloc:
                err_msg = f"Non-self request detected: {url} (method={req.method})"
                print(f"  [EXTERNAL REQUEST DETECTED] {err_msg}", file=sys.stderr)
                external_requests.append(err_msg)

        page.on("request", on_request)

        # Helper to check in-page recorded security policy violations
        def check_in_page_violations(context_name):
            try:
                events = page.evaluate("window._csp_violations || []")
                if events:
                    for ev in events:
                        msg = f"{context_name}: violatedDirective={ev.get('violatedDirective')}, blockedURI={ev.get('blockedURI')}"
                        print(f"  [SECURITY POLICY VIOLATION] {msg}", file=sys.stderr)
                        csp_violations.append(msg)
                    page.evaluate("window._csp_violations = [];")
            except Exception as e:
                print(f"Warning checking in-page violations: {e}", file=sys.stderr)

        csp_inject_script = """
            window._csp_violations = [];
            window.addEventListener('securitypolicyviolation', (e) => {
                window._csp_violations.push({
                    violatedDirective: e.violatedDirective,
                    blockedURI: e.blockedURI,
                    originalPolicy: e.originalPolicy
                });
            });
        """

        # --- A. Test Standalone Pages First ---
        standalone_pages = [
            ("Login Page", "/login.html"),
            ("Self-Registration Portal", "/register.html"),
            ("Password Reset Portal", "/password-reset.html"),
            ("Initial Setup Wizard", "/setup.html")
        ]

        print("\n--- Testing Standalone Pages ---")
        for page_name, page_path in standalone_pages:
            print(f"Testing {page_name} ({page_path})...")
            page.goto(f"{base_url}{page_path}", wait_until="networkidle")
            page.evaluate(csp_inject_script)
            page.wait_for_timeout(800)
            check_in_page_violations(page_name)

        # --- B. Test Authenticated Web Console (All 19 Tabs) ---
        print("\n--- Testing Authenticated Web Console (19 Tabs) ---")
        init_script = f"""
            localStorage.setItem('zclockid_token', '{token}');
            {csp_inject_script}
        """
        page.add_init_script(init_script)

        page.goto(f"{base_url}/", wait_until="networkidle")
        page.wait_for_timeout(1000)
        check_in_page_violations("Dashboard (Initial Load)")

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
                    # Nav reports triggers showTab('syslog'); switchLogsSubTab('compliance');
                    page.evaluate("if (typeof showTab === 'function') showTab('syslog'); if (typeof switchLogsSubTab === 'function') switchLogsSubTab('compliance');")
                else:
                    page.wait_for_selector(selector, state="visible", timeout=5000)
                    page.click(selector)

                page.wait_for_timeout(1000)
                check_in_page_violations(tab_name)

                # Capture Users screenshot when on Users tab
                if tab_name == "Users":
                    users_screenshot = SCREENSHOTS_DIR / "users.png"
                    page.screenshot(path=str(users_screenshot))
                    print(f"  -> Captured Users tab screenshot at {users_screenshot}")

            except Exception as e:
                print(f"  [ERROR] Failed navigating to {tab_name}: {e}", file=sys.stderr)
                js_errors.append(f"Navigation error on {tab_name}: {e}")

        # --- C. Test Modals Rendering & Capture Screenshot ---
        print("\n--- Testing Modals Rendering ---")
        try:
            # Switch back to users tab and open create user modal
            page.click("#nav-users")
            page.wait_for_timeout(500)
            page.evaluate("if (typeof openCreateUserModal === 'function') openCreateUserModal();")
            page.wait_for_timeout(600)
            check_in_page_violations("User Create Modal")

            modal_screenshot = SCREENSHOTS_DIR / "modals.png"
            page.screenshot(path=str(modal_screenshot))
            print(f"  -> Captured Modals screenshot at {modal_screenshot}")

            # Close modal
            page.evaluate("if (typeof closeModal === 'function') closeModal('create-user-modal');")
        except Exception as e:
            print(f"  [WARNING] Failed to open modal for screenshot: {e}", file=sys.stderr)

        context.close()
        browser.close()

    print(f"=================================================================")
    print(f"Summary:")
    print(f"  CSP Violations:        {len(csp_violations)}")
    print(f"  JS Page Errors:        {len(js_errors)}")
    print(f"  External Host Requests: {len(external_requests)}")
    print(f"=================================================================")

    if csp_violations or js_errors or external_requests:
        if csp_violations:
            print("\nCSP Violations encountered:", file=sys.stderr)
            for v in csp_violations:
                print(f"  - {v}", file=sys.stderr)
        if js_errors:
            print("\nJavaScript Page Errors encountered:", file=sys.stderr)
            for err in js_errors:
                print(f"  - {err}", file=sys.stderr)
        if external_requests:
            print("\nExternal / Non-Self Requests encountered:", file=sys.stderr)
            for r in external_requests:
                print(f"  - {r}", file=sys.stderr)
        sys.exit(1)

    print("Playwright CSP & Air-Gap Smoke Test PASSED: All 19 tabs + 4 portals clean!")
    sys.exit(0)


if __name__ == "__main__":
    main()
