"""
tests/test_get_db_hygiene.py: Regression tests for get_db definition hygiene and live router endpoints.
Verifies:
1. No module in api/ defines a function named 'get_db' except api/db/connection.py.
2. Full TestClient verification:
   - POST /api/v1/auth/login returns 200 and a valid token for a seeded admin user.
   - Using that token:
     - GET /api/v1/rbac/mappings -> 200 (not 500)
     - GET /api/v1/syslog/settings -> 200 (not 500)
     - GET /api/v1/api-keys -> 200 (not 500)
   - Uses a temporary SQLite DB via ZCLOCKID_DATA_DIR / DB_PATH without patching get_db or router internals.
"""

import ast
import os
import time
import secrets
import hashlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

import api.core.config as config
from api.db.init_db import init_db
from api.main import app


def test_no_shadow_get_db_definitions():
    """
    Item 2a: Fails if any module in api/ except api/db/connection.py defines
    a function named get_db.
    """
    repo_root = Path(__file__).resolve().parent.parent
    api_dir = repo_root / "api"
    assert api_dir.exists(), f"api directory not found at {api_dir}"

    shadow_definitions = []

    for root, _, files in os.walk(api_dir):
        for f in files:
            if not f.endswith(".py"):
                continue
            fpath = Path(root) / f
            rel_path = fpath.relative_to(repo_root)

            # api/db/connection.py is the canonical home of get_db
            if rel_path == Path("api/db/connection.py"):
                continue

            try:
                tree = ast.parse(fpath.read_text(encoding="utf-8"), filename=str(rel_path))
            except Exception as e:
                pytest.fail(f"Could not parse {rel_path}: {e}")

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == "get_db":
                        shadow_definitions.append(f"{rel_path}:{node.lineno}")

    assert not shadow_definitions, (
        f"Found illegal shadow 'get_db' definition(s) outside api/db/connection.py:\n"
        + "\n".join(shadow_definitions)
    )


def test_live_login_and_subsystem_endpoints_with_temp_db(tmp_path, monkeypatch):
    """
    Item 2b: Uses TestClient to verify:
    - POST /api/v1/auth/login -> 200 with seeded admin.
    - GET /api/v1/rbac/mappings -> 200 (not 500)
    - GET /api/v1/syslog/settings -> 200 (not 500)
    - GET /api/v1/api-keys -> 200 (not 500)
    Uses a temporary DB set via DB_PATH with no monkeypatching of get_db or router DB functions.
    """
    test_db = tmp_path / "test_live_appliance.db"
    
    # Configure DB_PATH across modules to the isolated temp DB
    monkeypatch.setattr(config, "DB_PATH", test_db)
    monkeypatch.setattr("api.routers.auth.DB_PATH", test_db)
    monkeypatch.setattr("api.routers.rbac.DB_PATH", test_db)
    monkeypatch.setattr("api.routers.syslog.DB_PATH", test_db)
    monkeypatch.setattr("api.routers.api_keys.DB_PATH", test_db)
    monkeypatch.setattr("api.services.security_service.DB_PATH", test_db)
    monkeypatch.setenv("ZCLOCKID_DATA_DIR", str(tmp_path))

    # Initialize the complete SQLite schema on test_db
    init_db(test_db)

    # Seed an admin user with pbkdf2 hash directly into admin_users table
    test_user = "testadmin"
    test_password = "<strong-regression-test-pass-2026!>"
    salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", test_password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()

    from api.db.connection import get_db
    with get_db(test_db) as conn:
        conn.execute(
            "INSERT INTO admin_users (username, salt, password_hash, email, created_at) VALUES (?, ?, ?, ?, ?)",
            (test_user, salt, pw_hash, "testadmin@corp.example.com", time.time())
        )
        conn.commit()

    client = TestClient(app, client=("127.0.0.1", 50000), base_url="http://127.0.0.1")

    # 1. Login should succeed and return 200 + token
    login_res = client.post("/api/v1/auth/login", json={
        "username": test_user,
        "password": test_password
    })
    assert login_res.status_code == 200, f"Login failed: {login_res.status_code} - {login_res.text}"
    login_data = login_res.json()
    token = login_data.get("token") or login_data.get("access_token")
    assert token, f"No token returned in login response: {login_data}"
    assert login_data.get("role") == "fulladmin"

    headers = {"Authorization": f"Bearer {token}"}

    # 2. RBAC mappings endpoint -> must not be 500
    rbac_res = client.get("/api/v1/rbac/mappings", headers=headers)
    assert rbac_res.status_code == 200, f"GET /rbac/mappings failed: {rbac_res.status_code} - {rbac_res.text}"
    assert "mappings" in rbac_res.json()

    # 3. Syslog settings endpoint -> must not be 500
    syslog_res = client.get("/api/v1/syslog/settings", headers=headers)
    assert syslog_res.status_code == 200, f"GET /syslog/settings failed: {syslog_res.status_code} - {syslog_res.text}"
    assert isinstance(syslog_res.json(), dict)

    # 4. API keys listing endpoint -> must not be 500
    apikeys_res = client.get("/api/v1/api-keys", headers=headers)
    assert apikeys_res.status_code == 200, f"GET /api-keys failed: {apikeys_res.status_code} - {apikeys_res.text}"
    assert isinstance(apikeys_res.json(), list)
