#!/usr/bin/env python3
"""
tests/csp_smoke.py - Playwright-based CSP & JS Error Smoke Test (v1.3.9)

Validates authenticated web console workflows in a real browser:
1. Logs in via POST /api/v1/auth/login using ZCLOCK_USER and ZCLOCK_PASS env vars.
2. Sets the session token in localStorage before navigation via page.add_init_script.
3. Clicks through Dashboard, Users, DNS, RADIUS, Self-Service, and Security tabs.
4. Fails immediately on any CSP violation event or uncaught JavaScript error (pageerror).
"""

import os
import sys
import time
import requests
import urllib3
from playwright.sync_api import sync_playwright

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    target_host = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ZCLOCK_HOST", "192.168.1.41")
    if not target_host.startswith("http://") and not target_host.startswith("https://"):
        base_url = f"https://{target_host}"
    else:
        base_url = target_host.rstrip("/")

    user = os.environ.get("ZCLOCK_USER")
    password = os.environ.get("ZCLOCK_PASS")

    if not user or not password:
        print("ERROR: Environment variables ZCLOCK_USER and ZCLOCK_PASS must be set.", file=sys.stderr)
        sys.exit(1)

    print(f"=================================================================")
    print(f" ZclockID Playwright CSP & Runtime Smoke Test")
    print(f" Target Host: {base_url}")
    print(f" User:        {user}")
    print(f"=================================================================")

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

        # Inject auth token into localStorage and add securitypolicyviolation listener
        init_script = f"""
            localStorage.setItem('zclockid_token', '{token}');
            window._csp_violations = [];
            window.addEventListener('securitypolicyviolation', (e) => {{
                window._csp_violations.push({{
                    violatedDirective: e.violatedDirective,
                    blockedURI: e.blockedURI,
                    originalPolicy: e.originalPolicy
                }});
            }});
        """
        page.add_init_script(init_script)

        # 3. Load root appliance UI
        print(f"Navigating to {base_url}/ ...")
        page.goto(f"{base_url}/", wait_until="networkidle")
        page.wait_for_timeout(1000)

        # Helper to check in-page recorded violations
        def check_in_page_violations(tab_name):
            try:
                events = page.evaluate("window._csp_violations || []")
                if events:
                    for ev in events:
                        msg = f"Tab {tab_name}: violatedDirective={ev.get('violatedDirective')}, blockedURI={ev.get('blockedURI')}"
                        print(f"  [SECURITY POLICY VIOLATION] {msg}", file=sys.stderr)
                        csp_violations.append(msg)
                    page.evaluate("window._csp_violations = [];")
            except Exception as e:
                print(f"Warning checking in-page violations: {e}", file=sys.stderr)

        check_in_page_violations("Initial Load (Dashboard)")

        # 4. Click through required tabs: Dashboard, Users, DNS, RADIUS, Self-Service, Security
        tabs_to_test = [
            ("Dashboard", "#nav-dashboard"),
            ("Users", "#nav-users"),
            ("DNS", "#nav-dns"),
            ("RADIUS", "#nav-radius"),
            ("Self-Service", "#nav-registrations"),
            ("Security", "#nav-rbac"),
        ]

        for tab_name, selector in tabs_to_test:
            print(f"Testing tab: {tab_name} ({selector})...")
            try:
                if tab_name == "Security":
                    page.evaluate("if (typeof toggleSecurityNavGroup === 'function') toggleSecurityNavGroup(true);")
                page.wait_for_selector(selector, state="visible", timeout=5000)
                page.click(selector)
                page.wait_for_timeout(1200)
                check_in_page_violations(tab_name)
            except Exception as e:
                print(f"  [ERROR] Failed navigating to {tab_name}: {e}", file=sys.stderr)
                js_errors.append(f"Navigation error on {tab_name}: {e}")

        context.close()
        browser.close()

    print(f"=================================================================")
    print(f"Summary:")
    print(f"  CSP Violations: {len(csp_violations)}")
    print(f"  JS Page Errors: {len(js_errors)}")
    print(f"=================================================================")

    if csp_violations or js_errors:
        if csp_violations:
            print("\nCSP Violations encountered:", file=sys.stderr)
            for v in csp_violations:
                print(f"  - {v}", file=sys.stderr)
        if js_errors:
            print("\nJavaScript Page Errors encountered:", file=sys.stderr)
            for err in js_errors:
                print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    print("Playwright CSP Smoke Test PASSED: All tabs verified clean!")
    sys.exit(0)

if __name__ == "__main__":
    main()
