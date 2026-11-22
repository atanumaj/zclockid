"""
tests/test_v1492_hardening.py: Invariant and unit tests for v1.4.9.2.

Verifies:
1. Operators must not add or remove members of privileged groups
   (Domain Admins, Enterprise Admins, Schema Admins, Administrators, plus adminCount=1
   or any group mapped to fulladmin in RBAC). Enforced in POST /users, PUT /users/{username},
   and group-membership endpoints (/groups/{group_name}/members). Fulladmin only; operator gets 403
   and an audit entry.
2. is_privileged_ad_user: fail closed — if ldbsearch lookup errors, treats the account as privileged (return True).
3. Tests:
   - operator creating a user with groups=["Domain Admins"] -> 403, user not created;
   - operator PUT adding an existing user to Domain Admins -> 403, membership unchanged;
   - operator removing someone from Domain Admins -> 403;
   - fulladmin can do all three;
   - ldbsearch failure -> operator blocked.
"""

import os
import time
import sqlite3
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from api.main import app
from api.services.samdb_service import _global_mock_samdb
from api.routers.users import (
    is_privileged_ad_user,
    is_privileged_ad_group,
    get_rbac_fulladmin_groups
)
import api.routers.users as users_mod


@pytest.fixture(autouse=True)
def init_test_db(tmp_path, monkeypatch):
    """Initializes isolated database for test cases."""
    db_file = tmp_path / "test_v1492.db"
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            role TEXT DEFAULT 'readonly',
            last_active REAL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            event_type TEXT,
            actor TEXT,
            target TEXT,
            status TEXT,
            details TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS rbac_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            principal_type TEXT NOT NULL,
            principal_name TEXT NOT NULL,
            role TEXT NOT NULL,
            description TEXT,
            created_at REAL,
            created_by TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS radius_bandwidth_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            download_mbps INTEGER,
            upload_mbps INTEGER,
            session_timeout_mins INTEGER,
            idle_timeout_mins INTEGER,
            daily_quota_mb INTEGER,
            ad_group TEXT,
            target_name TEXT,
            target_type TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS radius_user_bandwidth (
            username TEXT PRIMARY KEY,
            profile_id INTEGER,
            updated_at REAL
        )
    """)

    # Populate session tokens
    now_ts = time.time()
    c.execute(
        "INSERT INTO sessions (token, username, created_at, expires_at, role, last_active) VALUES (?, ?, ?, ?, ?, ?)",
        ("op_tok_1492", "operator_user", now_ts, now_ts + 3600, "operator", now_ts)
    )
    c.execute(
        "INSERT INTO sessions (token, username, created_at, expires_at, role, last_active) VALUES (?, ?, ?, ?, ?, ?)",
        ("admin_tok_1492", "admin_user", now_ts, now_ts + 3600, "fulladmin", now_ts)
    )

    # Insert an RBAC group mapping to fulladmin for testing dynamic privileged groups
    c.execute(
        "INSERT INTO rbac_mappings (principal_type, principal_name, role) VALUES ('group', 'Custom-SuperAdmins', 'fulladmin')"
    )

    conn.commit()
    conn.close()

    monkeypatch.setattr("api.routers.auth.DB_PATH", db_file)
    monkeypatch.setattr("api.routers.users.DB_PATH", db_file)
    monkeypatch.setattr("api.routers.rbac.DB_PATH", db_file)
    monkeypatch.setattr("api.core.config.DB_PATH", db_file)
    monkeypatch.setattr("api.db.init_db.DB_PATH", db_file)

    # Reset MockSamDB state
    db = _global_mock_samdb
    db.users.clear()
    db.groups.clear()
    db.calls.clear()

    # Default groups in MockSamDB
    db.groups["Domain Admins"] = {"description": "Domain Administrators", "members": set()}
    db.groups["Domain Users"] = {"description": "Standard Users", "members": set()}
    db.groups["Enterprise Admins"] = {"description": "Enterprise Admins", "members": set()}
    db.groups["Custom-SuperAdmins"] = {"description": "RBAC Fulladmin Group", "members": set()}
    db.groups["Special-AdminCountGroup"] = {"description": "AdminCount=1 Group", "members": set(), "adminCount": 1}
    db.groups["Normal-Group"] = {"description": "Normal Group", "members": set()}

    return db_file


# =============================================================================
# 1. POST /users: Privilege Checks on Creation
# =============================================================================

def test_operator_create_user_with_domain_admins_blocked(init_test_db):
    """
    Operator creating a user with groups=['Domain Admins'] -> 403,
    user NOT created, audit entry recorded.
    """
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    resp = client.post(
        "/api/v1/users",
        json={
            "username": "attacker1",
            "password": "SecurePassword!2026",
            "given_name": "Attacker",
            "surname": "One",
            "groups": ["Domain Admins"]
        },
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"
    assert "Domain Admins" in resp.json().get("detail", "")
    assert "requires the fulladmin role" in resp.json().get("detail", "")

    # Assert user was NOT created in MockSamDB
    assert "attacker1" not in db.users
    assert "attacker1" not in db.groups["Domain Admins"]["members"]

    # Verify audit log entry
    conn = sqlite3.connect(init_test_db)
    c = conn.cursor()
    c.execute("SELECT event_type, actor, target, status FROM audit_events WHERE event_type = 'PRIVILEGED_GROUP_MODIFICATION_BLOCKED'")
    audit_row = c.fetchone()
    conn.close()
    assert audit_row is not None
    assert audit_row[1] == "operator_user"
    assert audit_row[2] == "Domain Admins"
    assert audit_row[3] == "FAILURE"


def test_operator_create_user_with_target_group_domain_admins_blocked():
    """Operator creating user with target_group='Domain Admins' -> 403, not created."""
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    resp = client.post(
        "/api/v1/users",
        json={
            "username": "attacker2",
            "password": "SecurePassword!2026",
            "target_group": "Domain Admins"
        },
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert resp.status_code == 403
    assert "attacker2" not in db.users


def test_fulladmin_create_user_with_domain_admins_allowed():
    """Fulladmin creating a user with groups=['Domain Admins'] -> 201 Created."""
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    resp = client.post(
        "/api/v1/users",
        json={
            "username": "legitadmin",
            "password": "SecurePassword!2026",
            "given_name": "Legit",
            "surname": "Admin",
            "groups": ["Domain Admins"]
        },
        headers={"Authorization": "Bearer admin_tok_1492"}
    )
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
    assert "legitadmin" in db.users
    assert "legitadmin" in db.groups["Domain Admins"]["members"]


# =============================================================================
# 2. PUT /users/{username}: Privilege Checks on Add and Remove
# =============================================================================

def test_operator_put_adding_user_to_domain_admins_blocked():
    """
    Operator PUT adding an existing user to Domain Admins -> 403,
    membership unchanged, audit entry recorded.
    """
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    # Setup existing non-privileged user
    db.users["normuser"] = {"password": "NormalPass123!", "enabled": True}
    db.groups["Domain Users"]["members"].add("normuser")

    resp = client.put(
        "/api/v1/users/normuser",
        json={"groups": ["Domain Users", "Domain Admins"]},
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"
    assert "Domain Admins" in resp.json().get("detail", "")

    # Membership must be unchanged
    assert "normuser" not in db.groups["Domain Admins"]["members"]


def test_fulladmin_put_adding_user_to_domain_admins_allowed():
    """Fulladmin PUT adding an existing user to Domain Admins -> 200, membership updated."""
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    db.users["promoted_user"] = {"password": "NormalPass123!", "enabled": True}
    db.groups["Domain Users"]["members"].add("promoted_user")

    resp = client.put(
        "/api/v1/users/promoted_user",
        json={"groups": ["Domain Users", "Domain Admins"]},
        headers={"Authorization": "Bearer admin_tok_1492"}
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert "promoted_user" in db.groups["Domain Admins"]["members"]


def test_operator_removing_user_from_domain_admins_blocked():
    """
    Operator removing someone from Domain Admins -> 403,
    membership unchanged.
    """
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    db.users["admin_target"] = {"password": "AdminPass123!", "enabled": True}
    db.groups["Domain Admins"]["members"].add("admin_target")
    db.groups["Domain Users"]["members"].add("admin_target")

    resp = client.put(
        "/api/v1/users/admin_target",
        json={"groups": ["Domain Users"]},
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"

    # Membership must remain unchanged
    assert "admin_target" in db.groups["Domain Admins"]["members"]


def test_fulladmin_removing_user_from_domain_admins_allowed():
    """Fulladmin removing someone from Domain Admins -> 200, membership updated."""
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    db.users["demoted_admin"] = {"password": "AdminPass123!", "enabled": True}
    db.groups["Domain Admins"]["members"].add("demoted_admin")
    db.groups["Domain Users"]["members"].add("demoted_admin")

    resp = client.put(
        "/api/v1/users/demoted_admin",
        json={"groups": ["Domain Users"]},
        headers={"Authorization": "Bearer admin_tok_1492"}
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert "demoted_admin" not in db.groups["Domain Admins"]["members"]


# =============================================================================
# 3. Dedicated Group Membership Endpoints
# =============================================================================

def test_operator_blocked_on_group_membership_endpoints():
    """Operator adding or removing members via /groups/{name}/members -> 403."""
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    # 1. Add member to Domain Admins by operator -> 403
    r_add = client.post(
        "/api/v1/groups/Domain Admins/members",
        json={"username": "someone"},
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert r_add.status_code == 403
    assert "someone" not in db.groups["Domain Admins"]["members"]

    # 2. Remove member from Domain Admins by operator -> 403
    db.groups["Domain Admins"]["members"].add("someone")
    r_del = client.delete(
        "/api/v1/groups/Domain Admins/members/someone",
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert r_del.status_code == 403
    assert "someone" in db.groups["Domain Admins"]["members"]

    # 3. Fulladmin can add and remove
    r_fa_del = client.delete(
        "/api/v1/groups/Domain Admins/members/someone",
        headers={"Authorization": "Bearer admin_tok_1492"}
    )
    assert r_fa_del.status_code == 200
    assert "someone" not in db.groups["Domain Admins"]["members"]

    r_fa_add = client.post(
        "/api/v1/groups/Domain Admins/members",
        json={"username": "someone"},
        headers={"Authorization": "Bearer admin_tok_1492"}
    )
    assert r_fa_add.status_code == 200
    assert "someone" in db.groups["Domain Admins"]["members"]


# =============================================================================
# 4. Fail-Closed on ldbsearch Failure
# =============================================================================

def test_ldbsearch_failure_fails_closed_blocking_operator(monkeypatch):
    """
    Requirement 2 & 3:
    is_privileged_ad_user: fail closed — if the ldbsearch lookup errors,
    treat the account as privileged (return True) -> operator blocked with 403.
    """
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    # Setup user not in MockSamDB users so it falls through to ldbsearch
    clean_target = "external_user"

    # Simulate ldbsearch returning exit code 1 or error
    def failing_run_cmd(cmd, *args, **kwargs):
        if "ldbsearch" in cmd[0]:
            return (1, "", "ldbsearch: connection refused / database corrupted")
        return (0, "", "")

    monkeypatch.setattr(users_mod, "run_cmd", failing_run_cmd)

    # Verify is_privileged_ad_user fails closed
    assert is_privileged_ad_user(clean_target) is True

    # Operator trying to reset password on this user -> 403
    resp = client.post(
        f"/api/v1/users/{clean_target}/password",
        json={"new_password": "NewSecretPass123!"},
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert resp.status_code == 403, f"Expected 403 due to fail-closed ldbsearch, got {resp.status_code}"


# =============================================================================
# 5. RBAC & adminCount Group Escalation Protection
# =============================================================================

def test_rbac_and_admin_count_groups_protected_from_operator():
    """
    Groups mapped to fulladmin in RBAC (Custom-SuperAdmins) and groups with adminCount=1
    are recognized as privileged groups and protected from operator additions.
    """
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    # Verify is_privileged_ad_group recognizes RBAC and adminCount=1 groups
    assert is_privileged_ad_group("Custom-SuperAdmins") is True
    assert is_privileged_ad_group("Special-AdminCountGroup") is True
    assert is_privileged_ad_group("Normal-Group") is False

    # Operator cannot create user in RBAC fulladmin group
    r1 = client.post(
        "/api/v1/users",
        json={
            "username": "rbac_hacker",
            "password": "SecurePassword!2026",
            "groups": ["Custom-SuperAdmins"]
        },
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert r1.status_code == 403

    # Operator cannot create user in adminCount=1 group
    r2 = client.post(
        "/api/v1/users",
        json={
            "username": "admincount_hacker",
            "password": "SecurePassword!2026",
            "groups": ["Special-AdminCountGroup"]
        },
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert r2.status_code == 403


def test_nested_privileged_group_escalation_blocked():
    """
    Groups transitively nested inside privileged groups (e.g. Domain Admins -> Nested-Group)
    are recognized as privileged groups and operator cannot add members to them.
    """
    client = TestClient(app, client=("127.0.0.1", 50000))
    db = _global_mock_samdb

    # Create a nested group hierarchy:
    # Domain Admins contains Nested-Admin-Group
    db.groups["Nested-Admin-Group"] = {"description": "Child of Domain Admins", "members": set()}
    if "Domain Admins" not in db.groups:
        db.groups["Domain Admins"] = {"description": "Domain Admins", "members": set()}
    db.groups["Domain Admins"]["members"].add("Nested-Admin-Group")

    # Verify is_privileged_ad_group detects the transitive nesting
    assert is_privileged_ad_group("Nested-Admin-Group") is True

    # Operator attempting to create a user in Nested-Admin-Group must get 403
    resp_create = client.post(
        "/api/v1/users",
        json={
            "username": "nested_hacker",
            "password": "SecurePassword!2026",
            "groups": ["Nested-Admin-Group"]
        },
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert resp_create.status_code == 403
    assert "privileged" in resp_create.json()["detail"].lower()

    # Operator attempting to add a user to Nested-Admin-Group via /groups endpoint must get 403
    resp_add = client.post(
        "/api/v1/groups/Nested-Admin-Group/members",
        json={"username": "alice"},
        headers={"Authorization": "Bearer op_tok_1492"}
    )
    assert resp_add.status_code == 403
    assert "privileged" in resp_add.json()["detail"].lower()
