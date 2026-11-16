"""
ZclockID Sysvol Replication Authentication & Path Hardening Test Suite
=====================================================================
Verifies that Sysvol replication endpoints (/manifest, /file):
- Require valid peer sync secret (reject missing header with 401)
- Reject wrong secret with 401
- Enforce strict IP-to-secret binding (Partner A's secret from Partner B's IP rejected with 401)
- Accept correct secret from the bound IP with 200
- Reject readonly or operator user sessions on POST /file (returns 401/403)
- Reject path traversal (../sysvol_x/a, /etc/passwd, a/../../b, .tmp, empty) with 400
"""

import os
import json
import tempfile
import sqlite3
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.main import app
import api.routers.sysvol as sysvol_mod
import api.routers.auth as auth_mod
import api.services.security_service as sec_svc


@pytest.fixture(autouse=True)
def allow_test_ips(monkeypatch):
    """Allows test IP addresses in firewall security baseline during test suite runs."""
    orig_is_ip_allowed = sec_svc.is_ip_allowed
    monkeypatch.setattr(
        sec_svc,
        "is_ip_allowed",
        lambda ip, allowed: True if ip in ("testclient", "127.0.0.1", "192.168.180.43", "192.168.180.44") else orig_is_ip_allowed(ip, allowed)
    )


@pytest.fixture
def sysvol_test_env(tmp_path, monkeypatch):
    """Sets up an isolated SYSVOL root and partners configuration for testing."""
    sysvol_root = tmp_path / "sysvol"
    sysvol_root.mkdir(parents=True, exist_ok=True)
    
    # Create sample policy file inside sysvol
    policy_dir = sysvol_root / "Policies" / "{GUID-1234}"
    policy_dir.mkdir(parents=True, exist_ok=True)
    sample_file = policy_dir / "gpt.ini"
    sample_file.write_text("[General]\nVersion=1\n")

    partners_file = tmp_path / "sysvol_partners.json"
    partners_data = {
        "partners": [
            {
                "name": "DC-PartnerA",
                "ip_address": "192.168.180.43",
                "shared_secret": "secret_partner_a_12345"
            },
            {
                "name": "DC-PartnerB",
                "ip_address": "192.168.180.44",
                "shared_secret": "secret_partner_b_67890"
            }
        ]
    }
    partners_file.write_text(json.dumps(partners_data, indent=2))

    local_secret_file = tmp_path / "sysvol_secret"
    local_secret_file.write_text("local_appliance_secret_99999\n")

    monkeypatch.setattr(sysvol_mod, "PHYSICAL_SYSVOL_DIR", sysvol_root)
    monkeypatch.setattr(sysvol_mod, "SYSVOL_PARTNERS_FILE", partners_file)
    monkeypatch.setattr(sysvol_mod, "SYSVOL_LOCAL_SECRET_FILE", local_secret_file)

    # Mock samba-tool ntacl sysvolreset execution to prevent calling host system
    monkeypatch.setattr(sysvol_mod, "run_cmd", lambda cmd, **kwargs: (0, "Mock success", ""))

    return {
        "sysvol_root": sysvol_root,
        "sample_file": sample_file,
        "partners_file": partners_file
    }


@pytest.fixture
def client():
    # Emulate connection originating from localhost reverse proxy so X-Real-IP is trusted
    return TestClient(app, client=("127.0.0.1", 50000))


def test_no_header_returns_401(client, sysvol_test_env):
    """Calls to replication endpoints without X-Zclock-Sync-Secret header return 401."""
    # GET /manifest
    resp = client.get("/api/v1/sysvol/manifest", headers={"X-Real-IP": "192.168.180.43"})
    assert resp.status_code == 401
    assert "Missing X-Zclock-Sync-Secret" in resp.json()["detail"]

    # GET /file
    resp = client.get("/api/v1/sysvol/file?rel_path=Policies/{GUID-1234}/gpt.ini", headers={"X-Real-IP": "192.168.180.43"})
    assert resp.status_code == 401
    assert "Missing X-Zclock-Sync-Secret" in resp.json()["detail"]

    # POST /file
    payload = {
        "rel_path": "Policies/{GUID-1234}/test.txt",
        "content_base64": "68656c6c6f",
        "mtime": 1700000000.0
    }
    resp = client.post("/api/v1/sysvol/file", json=payload, headers={"X-Real-IP": "192.168.180.43"})
    assert resp.status_code == 401
    assert "Missing X-Zclock-Sync-Secret" in resp.json()["detail"]


def test_wrong_secret_returns_401(client, sysvol_test_env):
    """Calls with incorrect secret header return 401."""
    headers = {
        "X-Real-IP": "192.168.180.43",
        "X-Zclock-Sync-Secret": "wrong_invalid_secret_value"
    }
    resp = client.get("/api/v1/sysvol/manifest", headers=headers)
    assert resp.status_code == 401
    assert "Invalid secret" in resp.json()["detail"]


def test_partner_a_secret_sent_from_partner_b_ip_returns_401(client, sysvol_test_env):
    """
    Partner A's secret sent from Partner B's IP address is rejected with 401.
    Ties each secret strictly to its registered peer IP.
    """
    headers = {
        "X-Real-IP": "192.168.180.44",  # Partner B's IP
        "X-Zclock-Sync-Secret": "secret_partner_a_12345"  # Partner A's Secret
    }
    resp = client.get("/api/v1/sysvol/manifest", headers=headers)
    assert resp.status_code == 401
    assert "Invalid secret" in resp.json()["detail"]

    # Also test unregistered/unknown peer IP
    headers_unknown = {
        "X-Real-IP": "192.168.180.99",
        "X-Zclock-Sync-Secret": "secret_partner_a_12345"
    }
    resp_unknown = client.get("/api/v1/sysvol/manifest", headers=headers_unknown)
    assert resp_unknown.status_code == 401
    assert "not a registered partner" in resp_unknown.json()["detail"]


def test_local_secret_rejected_on_inbound_calls(client, sysvol_test_env):
    """The appliance's own local secret is rejected on inbound calls."""
    headers = {
        "X-Real-IP": "192.168.180.43",
        "X-Zclock-Sync-Secret": "local_appliance_secret_99999"
    }
    resp = client.get("/api/v1/sysvol/manifest", headers=headers)
    assert resp.status_code == 401
    assert "Invalid secret" in resp.json()["detail"]


def test_correct_secret_from_right_ip_returns_200(client, sysvol_test_env):
    """Calls with the registered partner's secret originating from their IP succeed with 200."""
    headers = {
        "X-Real-IP": "192.168.180.43",
        "X-Zclock-Sync-Secret": "secret_partner_a_12345"
    }
    # 1. Manifest
    resp = client.get("/api/v1/sysvol/manifest", headers=headers)
    assert resp.status_code == 200
    manifest = resp.json()["manifest"]
    assert "Policies/{GUID-1234}/gpt.ini" in manifest

    # 2. File Download
    resp_file = client.get("/api/v1/sysvol/file?rel_path=Policies/{GUID-1234}/gpt.ini", headers=headers)
    assert resp_file.status_code == 200
    assert resp_file.content == b"[General]\nVersion=1\n"

    # 3. File Upload
    payload = {
        "rel_path": "Policies/{GUID-1234}/replicated_file.txt",
        "content_base64": b"hello peer replication".hex(),
        "mtime": 1700000000.0
    }
    resp_upload = client.post("/api/v1/sysvol/file", json=payload, headers=headers)
    assert resp_upload.status_code == 200
    assert resp_upload.json()["status"] == "success"

    # Verify file was written to disk
    written = sysvol_test_env["sysvol_root"] / "Policies" / "{GUID-1234}" / "replicated_file.txt"
    assert written.exists()
    assert written.read_bytes() == b"hello peer replication"


def test_readonly_or_operator_session_on_post_file_rejected(client, sysvol_test_env, tmp_path, monkeypatch):
    """
    POST /file accepts ONLY the peer sync secret.
    User session tokens (operator, readonly) are refused with 401.
    On the separate admin route (POST /admin/file), operator is refused with 403.
    """
    # Set up auth sqlite DB with sessions for readonly, operator, fulladmin
    db_file = tmp_path / "test_auth_sysvol.db"
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
    import time
    now = time.time()
    tokens = {
        "readonly": "tok_ro_sysvol",
        "operator": "tok_op_sysvol",
        "fulladmin": "tok_fa_sysvol"
    }
    for role, tok in tokens.items():
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at, role, last_active) VALUES (?, ?, ?, ?, ?, ?)",
            (tok, f"user_{role}", now, now + 3600, role, now)
        )
    conn.commit()
    conn.close()

    monkeypatch.setattr(auth_mod, "DB_PATH", db_file)

    payload = {
        "rel_path": "Policies/{GUID-1234}/admin_test.txt",
        "content_base64": b"test content".hex(),
        "mtime": 1700000000.0
    }

    # 1. POST /api/v1/sysvol/file with Authorization Bearer token (operator) and no sync secret -> 401
    resp_op = client.post(
        "/api/v1/sysvol/file",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['operator']}"}
    )
    assert resp_op.status_code == 401
    assert "Missing X-Zclock-Sync-Secret" in resp_op.json()["detail"]

    # Call peer replication endpoint with readonly Bearer token -> 401
    resp_ro = client.post(
        "/api/v1/sysvol/file",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['readonly']}"}
    )
    assert resp_ro.status_code == 401
    assert "Missing X-Zclock-Sync-Secret" in resp_ro.json()["detail"]

    # 2. Call separate admin route POST /api/v1/sysvol/admin/file with operator token -> 403 (requires fulladmin)
    resp_admin_op = client.post(
        "/api/v1/sysvol/admin/file",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['operator']}"}
    )
    assert resp_admin_op.status_code == 403

    # Call separate admin route with readonly token -> 403
    resp_admin_ro = client.post(
        "/api/v1/sysvol/admin/file",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['readonly']}"}
    )
    assert resp_admin_ro.status_code == 403

    # Fulladmin token on POST /admin/file succeeds
    resp_admin_fa = client.post(
        "/api/v1/sysvol/admin/file",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['fulladmin']}"}
    )
    assert resp_admin_fa.status_code == 200


def test_path_traversal_and_file_safety_rejected_with_400(client, sysvol_test_env):
    """
    Verifies that Path.is_relative_to(safe_root) rejects:
    - rel_path of ../sysvol_x/a
    - /etc/passwd
    - a/../../b
    - .tmp suffixes
    - empty paths
    """
    headers = {
        "X-Real-IP": "192.168.180.43",
        "X-Zclock-Sync-Secret": "secret_partner_a_12345"
    }

    traversal_paths = [
        "../sysvol_x/a",
        "/etc/passwd",
        "a/../../b",
        "Policies/test.tmp",
        "Policies/script.vbs.tmp",
        "",
        "   "
    ]

    for p in traversal_paths:
        # Test GET /file
        resp_get = client.get(f"/api/v1/sysvol/file?rel_path={p}", headers=headers)
        assert resp_get.status_code == 400, f"Expected 400 for path '{p}', got {resp_get.status_code}"

        # Test POST /file
        payload = {
            "rel_path": p,
            "content_base64": b"malicious content".hex(),
            "mtime": 1700000000.0
        }
        resp_post = client.post("/api/v1/sysvol/file", json=payload, headers=headers)
        assert resp_post.status_code == 400, f"Expected 400 for path '{p}', got {resp_post.status_code}"
