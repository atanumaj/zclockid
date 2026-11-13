"""
ZclockID Authentication Coverage Test Suite
===========================================
Verifies that authentication is default-on for the entire ZclockID API.
Iterates through all routes in app.routes, invokes every non-public route
without an authentication token, and asserts an HTTP 401 Unauthorized response.
Also verifies role hierarchy (fulladmin > operator > report > readonly),
setup.lock 403 protection, and X-Real-IP reverse proxy trust restrictions.
Operates completely offline without requiring Samba, database fixtures, or network access.
"""

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
from starlette.requests import Request

from api.main import app
from api.routers.auth import PUBLIC_PATHS, is_public_path
import api.routers.auth as auth_mod
from api.services.security_service import get_client_ip
import api.services.security_service as sec_svc


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


def _collect_api_routes(routes):
    """Recursively unpacks all APIRoutes across top-level and included routers."""
    collected = []
    for r in routes:
        if hasattr(r, "path") and r.path and hasattr(r, "methods"):
            collected.append(r)
        elif hasattr(r, "routes"):
            collected.extend(_collect_api_routes(r.routes))
        elif hasattr(r, "original_router") and hasattr(r.original_router, "routes"):
            collected.extend(_collect_api_routes(r.original_router.routes))
    return collected


def test_auth_coverage_all_non_public_routes_return_401():
    """
    Asserts that every route in app.routes that is not in PUBLIC_PATHS
    returns HTTP 401 when accessed without an Authorization token.
    """
    client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))
    all_routes = _collect_api_routes(app.routes)

    assert len(all_routes) > 0, "No API routes detected in application"

    tested_non_public = 0
    exempt_public = 0

    for route in all_routes:
        path = route.path
        if is_public_path(path):
            exempt_public += 1
            continue

        # Replace any path parameter placeholders (e.g. {username}, {rule_id}) with dummy value
        test_path = re.sub(r"\{[^}]+\}", "1", path)

        # Pick an active HTTP method for the route, ignoring HEAD and OPTIONS
        methods = [m for m in route.methods if m not in ("HEAD", "OPTIONS")]
        method = methods[0] if methods else "GET"

        # Make call without token / Authorization header
        response = client.request(method, test_path)

        assert response.status_code == 401, (
            f"Security Violation: {method} {path} (requested as {test_path}) returned "
            f"HTTP {response.status_code} instead of 401 Unauthorized.\nBody: {response.text}"
        )
        tested_non_public += 1

    print(f"\n[PASS] Verified auth default-on across {tested_non_public} endpoints ({exempt_public} public routes exempt).")
    assert tested_non_public > 50, f"Expected >50 protected endpoints, only found {tested_non_public}"


def test_public_paths_remain_accessible_without_token():
    """Verifies that explicitly declared public endpoints do not return 401."""
    client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

    # 1. Setup status must be public
    res_status = client.get("/api/v1/setup/status")
    assert res_status.status_code != 401, f"/setup/status returned 401: {res_status.text}"

    # 2. Public self-registration config must be public
    res_reg_cfg = client.get("/api/v1/public/register/config")
    assert res_reg_cfg.status_code != 401, f"/public/register/config returned 401: {res_reg_cfg.text}"

    # 3. Public SSPR config must be public
    res_sspr_cfg = client.get("/api/v1/self-service/password/config")
    assert res_sspr_cfg.status_code != 401, f"/self-service/password/config returned 401: {res_sspr_cfg.text}"

    # 4. Auth login must be public (not 401 for missing token; returns 422 for missing body)
    res_login = client.post("/api/v1/auth/login", json={})
    assert res_login.status_code != 401, f"/auth/login returned 401: {res_login.text}"


def test_setup_provision_locked_returns_403(tmp_path):
    """Verifies /api/v1/setup/provision returns 403 once setup.lock exists."""
    lock_file = tmp_path / "setup.lock"
    lock_file.write_text("PROVISIONED=1\n")

    orig_lock = auth_mod.SETUP_LOCK_FILE
    auth_mod.SETUP_LOCK_FILE = lock_file
    try:
        client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))
        res = client.post("/api/v1/setup/provision", json={})
        assert res.status_code == 403, f"Expected 403 when setup.lock exists, got {res.status_code}: {res.text}"
    finally:
        auth_mod.SETUP_LOCK_FILE = orig_lock


def test_role_hierarchy_permissions(tmp_path):
    """
    Verifies role hierarchy: fulladmin > operator > report > readonly.
    - readonly: can GET non-fulladmin, GET /system/status, /system/auth-stats/24h, /services,
      can POST /auth/change-password; blocked (403) on mutating and fulladmin routes.
    - operator: can mutate non-fulladmin; blocked (403) on fulladmin & setting changes.
    - fulladmin: permitted across all endpoints.
    """
    db_file = tmp_path / "test_auth.db"
    conn = sqlite3.connect(db_file)
    conn.execute("""
        CREATE TABLE sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            role TEXT DEFAULT 'readonly',
            last_active REAL
        )
    """)
    now = time.time()
    tokens = {
        "readonly": "tok_ro_123",
        "report": "tok_rep_123",
        "operator": "tok_op_123",
        "fulladmin": "tok_fa_123"
    }
    for role, tok in tokens.items():
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at, role, last_active) VALUES (?, ?, ?, ?, ?, ?)",
            (tok, f"user_{role}", now, now + 3600, role, now)
        )
    conn.commit()
    conn.close()

    orig_db = auth_mod.DB_PATH
    auth_mod.DB_PATH = db_file
    try:
        client = TestClient(app, raise_server_exceptions=False, client=("127.0.0.1", 50000))

        # 1. Readonly user: GET /users passes auth check (not 401 or 403)
        ro_headers = {"Authorization": f"Bearer {tokens['readonly']}"}
        res_ro_get = client.get("/api/v1/users", headers=ro_headers)
        assert res_ro_get.status_code not in (401, 403), f"Readonly GET failed: {res_ro_get.status_code}"

        # 2. Readonly user: POST /users must return 403 (mutating requires operator)
        res_ro_post = client.post("/api/v1/users", headers=ro_headers)
        assert res_ro_post.status_code == 403, f"Readonly POST should return 403, got {res_ro_post.status_code}"

        # 3. Readonly user: GET /system/status, /system/auth-stats/24h, /services passes auth check
        for allowed_path in ("/api/v1/system/status", "/api/v1/system/auth-stats/24h", "/api/v1/services"):
            res_allowed = client.get(allowed_path, headers=ro_headers)
            assert res_allowed.status_code not in (401, 403), f"Readonly GET {allowed_path} should be allowed, got {res_allowed.status_code}"

        # 4. Readonly user: Other /system, /services, /backups routes must return 403 (fulladmin-only)
        for fulladmin_path in ("/api/v1/system/update/info", "/api/v1/services/samba-ad-dc/logs", "/api/v1/backups"):
            res_denied = client.get(fulladmin_path, headers=ro_headers)
            assert res_denied.status_code == 403, f"Readonly GET {fulladmin_path} should return 403, got {res_denied.status_code}"

        # 5. Readonly user: POST /auth/change-password passes role check (not 401 or 403)
        res_ro_cp = client.post(
            "/api/v1/auth/change-password",
            headers=ro_headers,
            json={"current_password": "test", "new_password": "test"}
        )
        assert res_ro_cp.status_code not in (401, 403), f"Readonly POST /auth/change-password should be allowed, got {res_ro_cp.status_code}"

        # 6. Operator user: POST /users passes auth (not 401 or 403; returns 422 for missing body)
        op_headers = {"Authorization": f"Bearer {tokens['operator']}"}
        res_op_post = client.post("/api/v1/users", headers=op_headers)
        assert res_op_post.status_code not in (401, 403), f"Operator POST failed: {res_op_post.status_code}"

        # 7. Operator user: other system route returns 403 (requires fulladmin)
        res_op_sys = client.get("/api/v1/system/update/info", headers=op_headers)
        assert res_op_sys.status_code == 403, f"Operator GET /system/update/info should return 403, got {res_op_sys.status_code}"

        # 8. Operator user: POST /radius/settings must return 403 (setting changes require fulladmin)
        res_op_set = client.post("/api/v1/radius/settings", headers=op_headers)
        assert res_op_set.status_code == 403, f"Operator POST setting change should return 403, got {res_op_set.status_code}"

        # 9. Fulladmin user: GET /system/update/info passes auth (not 401 or 403)
        fa_headers = {"Authorization": f"Bearer {tokens['fulladmin']}"}
        res_fa_sys = client.get("/api/v1/system/update/info", headers=fa_headers)
        assert res_fa_sys.status_code not in (401, 403), f"Fulladmin GET /system/update/info failed: {res_fa_sys.status_code}"

    finally:
        auth_mod.DB_PATH = orig_db


def test_get_client_ip_proxy_trust():
    """Verifies get_client_ip only trusts X-Real-IP and X-Forwarded-For from 127.0.0.1."""
    # Direct from 127.0.0.1 with X-Real-IP -> trust header
    scope_local = {
        "type": "http",
        "client": ("127.0.0.1", 54321),
        "headers": [(b"x-real-ip", b"203.0.113.195")]
    }
    req_local = Request(scope_local)
    assert get_client_ip(req_local) == "203.0.113.195"

    # Direct from external IP with spoofed X-Real-IP -> do NOT trust header, return client host
    scope_ext = {
        "type": "http",
        "client": ("198.51.100.42", 54321),
        "headers": [(b"x-real-ip", b"127.0.0.1"), (b"x-forwarded-for", b"10.0.0.1")]
    }
    req_ext = Request(scope_ext)
    assert get_client_ip(req_ext) == "198.51.100.42"


if __name__ == "__main__":
    orig_is_ip_allowed = sec_svc.is_ip_allowed
    sec_svc.is_ip_allowed = lambda ip, allowed: True if ip in ("testclient", "127.0.0.1") else orig_is_ip_allowed(ip, allowed)

    print("Running test_auth_coverage_all_non_public_routes_return_401...")
    test_auth_coverage_all_non_public_routes_return_401()
    print("Running test_public_paths_remain_accessible_without_token...")
    test_public_paths_remain_accessible_without_token()
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        print("Running test_setup_provision_locked_returns_403...")
        test_setup_provision_locked_returns_403(p)
        print("Running test_role_hierarchy_permissions...")
        test_role_hierarchy_permissions(p)
    print("Running test_get_client_ip_proxy_trust...")
    test_get_client_ip_proxy_trust()
    print("ALL TESTS PASSED SUCCESSFULLY!")
