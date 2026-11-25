"""
tests/test_sqlite_wal_backup.py: Automated tests for SQLite connection manager and WAL backup integrity.
Verifies that:
1. get_db() context manager properly applies WAL mode, busy_timeout=5000, foreign_keys=ON, and secure_delete=ON.
2. get_db() always closes the connection upon context manager exit or explicit close().
3. A backup taken immediately after a write to a WAL-mode database contains that write intact.
4. The system backup API extracts a consistent database snapshot including un-checkpointed writes.
"""

import sqlite3
import time
import tempfile
import tarfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.db.connection import get_db, DBConnectionContext
from api.db.init_db import init_db
from api.main import app
import api.core.config as config
import api.routers.system as sys_mod
import api.routers.auth as auth_mod
import api.services.security_service as sec_svc
import api.main as main_mod

client = TestClient(app, client=("127.0.0.1", 50000), base_url="http://127.0.0.1")
ADMIN_HEADERS = {"Authorization": "Bearer tok_wal_admin"}


def test_get_db_pragmas_and_automatic_close(tmp_path):
    """Verifies that get_db() enforces WAL, busy_timeout=5000, foreign_keys=1, secure_delete=1 and closes."""
    test_db = tmp_path / "pragma_test.db"

    with get_db(test_db) as conn:
        conn.execute("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")
        conn.execute("INSERT INTO t1 (val) VALUES ('test_val')")
        conn.commit()

        jm = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        bt = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
        fk = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        sd = conn.execute("PRAGMA secure_delete;").fetchone()[0]

        assert jm.lower() == "wal", f"Expected WAL journal mode, got {jm}"
        assert bt == 5000, f"Expected 5000ms busy timeout, got {bt}"
        assert fk == 1, f"Expected foreign keys ON (1), got {fk}"
        assert sd == 1, f"Expected secure delete ON (1), got {sd}"

    # Verify that attempting to operate on the connection after context exit fails closed
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")


def test_backup_contains_immediate_write(tmp_path):
    """
    Verifies that when WAL mode is active, a backup taken immediately after a write
    contains that write intact (verifying backup API + checkpoint mechanism).
    """
    src_db = tmp_path / "live.db"
    backup_db = tmp_path / "backup.db"

    init_db(src_db)

    # 1. Write a record immediately into the WAL-mode database
    test_username = f"wal_user_{int(time.time())}"
    with get_db(src_db) as conn:
        conn.execute(
            "INSERT INTO admin_users (username, salt, password_hash, email, created_at) VALUES (?, ?, ?, ?, ?)",
            (test_username, "salt_xyz", "hash_abc", "wal@corp.example.com", time.time())
        )
        conn.commit()

    # 2. Immediately execute backup using the online sqlite3 backup API with checkpoint
    with get_db(src_db) as src_conn:
        src_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        with get_db(backup_db) as dst_conn:
            src_conn.backup(dst_conn)

    # 3. Open the backup database directly in an isolated connection and verify the write exists
    with get_db(backup_db) as check_conn:
        cursor = check_conn.cursor()
        cursor.execute("SELECT username, email FROM admin_users WHERE username = ?", (test_username,))
        row = cursor.fetchone()
        assert row is not None, f"Record for {test_username} was missing from backup database!"
        assert row["username"] == test_username
        assert row["email"] == "wal@corp.example.com"


def test_system_backup_endpoint_contains_fresh_write(monkeypatch, tmp_path):
    """
    Verifies that the POST /api/v1/system/backup endpoint produces an archive
    whose extracted zclockid.db contains changes written right before backup.
    """
    test_db = tmp_path / "system_live.db"
    init_db(test_db)

    monkeypatch.setattr(config, "DB_PATH", test_db)
    monkeypatch.setattr(sys_mod, "DB_PATH", test_db)
    monkeypatch.setattr(auth_mod, "DB_PATH", test_db)

    backup_storage = tmp_path / "backups"
    backup_storage.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "BACKUP_DIR", backup_storage)
    monkeypatch.setattr(sys_mod, "BACKUP_DIR", backup_storage)

    # Allow testclient
    monkeypatch.setattr(sec_svc, "is_ip_allowed", lambda ip, allowed: True)
    monkeypatch.setattr(main_mod, "is_ip_allowed", lambda ip, allowed: True)

    # Insert admin session
    now = time.time()
    with get_db(test_db) as conn:
        conn.execute(
            "INSERT INTO sessions (token, username, role, created_at, expires_at, last_active) VALUES (?, ?, ?, ?, ?, ?)",
            ("tok_wal_admin", "admin", "fulladmin", now, now + 3600, now)
        )
        conn.commit()

    # Perform a write immediately before invoking the backup endpoint
    unique_user = f"sys_backup_usr_{int(time.time())}"
    with get_db(test_db) as conn:
        conn.execute(
            "INSERT INTO admin_users (username, salt, password_hash, email, created_at) VALUES (?, ?, ?, ?, ?)",
            (unique_user, "s_salt", "s_hash", "sys@corp.example.com", time.time())
        )
        conn.commit()

    # Trigger backup
    res = client.post("/api/v1/backups/create", json={"passphrase": None}, headers=ADMIN_HEADERS)
    assert res.status_code == 200, f"Backup failed: {res.text}"
    backup_meta = res.json()
    archive_name = backup_meta.get("filename")
    assert archive_name, "Backup response missing filename"

    archive_path = backup_storage / archive_name
    assert archive_path.exists(), f"Backup file {archive_path} not found"

    # Extract the archive and verify the database inside contains the freshly written user
    extract_dir = tmp_path / "extracted_backup"
    extract_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(extract_dir)

    extracted_db = extract_dir / "appliance" / "zclockid.db"
    assert extracted_db.exists(), f"Extracted database not found at {extracted_db}"

    with get_db(extracted_db) as ext_conn:
        row = ext_conn.execute("SELECT * FROM admin_users WHERE username = ?", (unique_user,)).fetchone()
        assert row is not None, f"Freshly written user {unique_user} missing from system backup archive!"
        assert row["username"] == unique_user


def test_db_connection_context_attribute_forwarding(tmp_path):
    """
    Test Item 3: Verifies that DBConnectionContext forwards attributes like
    row_factory, isolation_level, text_factory to the real connection.
    Specifically tests that get_db(...).isolation_level = None followed by
    VACUUM after an uncommitted insert does not raise (VACUUM cannot run in a transaction).
    """
    test_db = tmp_path / "attr_test.db"
    db_ctx = get_db(test_db)
    
    # Test setting isolation_level on db_ctx directly via __setattr__
    db_ctx.isolation_level = None  # Autocommit mode
    assert db_ctx.isolation_level is None

    # An insert without explicit commit
    db_ctx.execute("CREATE TABLE t_autocommit (id INTEGER PRIMARY KEY, msg TEXT)")
    db_ctx.execute("INSERT INTO t_autocommit (msg) VALUES ('vacuum_test')")

    # In autocommit mode (isolation_level = None), VACUUM is allowed and does not raise
    # "cannot VACUUM from within a transaction"
    db_ctx.execute("VACUUM")

    # Verify custom row_factory forwarding
    db_ctx.row_factory = sqlite3.Row
    row = db_ctx.execute("SELECT * FROM t_autocommit").fetchone()
    assert row["msg"] == "vacuum_test"

    db_ctx.close()


def test_get_auth_stats_24h_returns_db_events(tmp_path, monkeypatch):
    """
    Test Item 5: Verifies that get_auth_stats_24h queries DB audit records via
    the corrected import from api.db.connection and returns aggregated counts.
    """
    test_db = tmp_path / "auth_stats.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db(test_db)

    now = time.time()
    # Insert audit events for recent activity (within 24h)
    with get_db(test_db) as conn:
        conn.execute(
            "INSERT INTO audit_events (event_type, actor, target, status, details, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("AUTH_LOGIN_SUCCESS", "test_admin", "appliance", "SUCCESS", "{}", now - 3600)
        )
        conn.execute(
            "INSERT INTO audit_events (event_type, actor, target, status, details, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("AUTH_LOGIN_FAILED", "attacker", "appliance", "FAILED", "{}", now - 1800)
        )
        conn.commit()

    stats = sys_mod.get_auth_stats_24h()
    assert isinstance(stats, dict)
    assert stats.get("status") == "success"
    assert "total_24h" in stats
    assert stats["total_24h"] > 0
    assert "hourly" in stats
    assert len(stats["hourly"]) == 24

    # Verify that the hourly buckets reflect our injected DB events
    matching_admin_hours = [b for b in stats["hourly"] if b["admin"] > 0]
    assert len(matching_admin_hours) > 0, "DB admin auth event not reflected in hourly"
    matching_failed_hours = [b for b in stats["hourly"] if b["failed"] > 0]
    assert len(matching_failed_hours) > 0, "DB failed auth event not reflected in hourly"


def test_get_auth_stats_24h_excludes_non_auth_events_and_synthetic_data(tmp_path, monkeypatch):
    """
    Verifies that get_auth_stats_24h does not inject synthetic counts and ignores
    non-authentication audit events such as SYSVOL_SYNC_AUTH_REJECTED or UPDATE_CHECKED.
    """
    test_db = tmp_path / "auth_stats_clean.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db(test_db)

    now = time.time()
    with get_db(test_db) as conn:
        conn.execute(
            "INSERT INTO audit_events (event_type, actor, target, status, details, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("SYSVOL_SYNC_AUTH_REJECTED", "peer", "192.168.180.44", "FAILED", "{}", now - 600)
        )
        conn.execute(
            "INSERT INTO audit_events (event_type, actor, target, status, details, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("UPDATE_CHECKED", "admin", "appliance", "SUCCESS", "{}", now - 300)
        )
        conn.commit()

    stats = sys_mod.get_auth_stats_24h()
    assert stats["total_24h"] == 0
    assert stats["failed_count"] == 0
    assert stats["success_count"] == 0


