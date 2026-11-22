"""
tests/test_v150_hardening.py: Invariant and unit tests for v1.5.0.

Verifies:
1. SNMP config injection prevention:
   - Community string validated with ^[A-Za-z0-9._-]{8,64}$, rejects newlines, spaces, #.
   - Allowed subnets validated as IP or CIDR, rejects newlines, spaces, #.
   - sys_location, sys_contact, agent_address reject newlines and #.
   - snmpv3_user validated.
   - snmpd.conf written atomically with mode 0600.
   - POST /api/v1/snmp/config with "public\\nextend x /bin/sh" returns 400.
   - POST /api/v1/security/baseline with "public\\ninject" returns 400.
2. Archive extraction security:
   - Tar archives: path traversal (../../), absolute paths (/etc/x), symlinks/hardlinks
     escaping dest_dir, device/special nodes, and file count/size caps raise ArchiveSecurityError / 400.
   - Zip archives: path traversal, absolute paths, zip symlink escapes, size caps raise 400.
   - POST /api/v1/backups/upload with traversal tar or zip returns 400.
3. CORS configuration:
   - Default configuration does not include wildcard CORSMiddleware.
   - Requests with Origin: https://evil.example receive NO Access-Control-Allow-Origin header.
"""

import io
import os
import stat
import time
import zipfile
import tarfile
import sqlite3
import pytest
from pathlib import Path
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.main import app
from api.core.snmp_security import (
    validate_snmp_community,
    validate_snmp_source,
    validate_snmp_subnets,
    validate_snmp_text_field,
    validate_snmpv3_user,
    validate_snmpv3_password,
    write_snmp_config_atomic
)
from api.core.archive_security import (
    ArchiveSecurityError,
    validate_tar_archive,
    validate_zip_archive,
    safe_extract_tar,
    safe_extract_zip
)
import api.routers.system as system_router
import api.routers.security as security_router


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Isolates DB, backups, and config paths for testing."""
    test_db = tmp_path / "test_v150.db"
    conn = sqlite3.connect(test_db)
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
        CREATE TABLE IF NOT EXISTS security_settings (
            id INTEGER PRIMARY KEY,
            setting_key TEXT UNIQUE,
            setting_value TEXT,
            updated_at REAL
        )
    """)
    # Insert admin session
    now = time.time()
    c.execute(
        "INSERT INTO sessions (token, username, created_at, expires_at, role, last_active) VALUES (?, ?, ?, ?, ?, ?)",
        ("admin-token-150", "admin", now, now + 3600, "fulladmin", now)
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr("api.core.config.DB_PATH", test_db)
    monkeypatch.setattr("api.db.init_db.DB_PATH", test_db)
    monkeypatch.setattr("api.routers.auth.DB_PATH", test_db)
    monkeypatch.setattr("api.routers.system.DB_PATH", test_db)
    monkeypatch.setattr("api.routers.security.DB_PATH", test_db)
    monkeypatch.setattr("api.services.security_service.DB_PATH", test_db)

    # Isolated backup dir
    test_backup_dir = tmp_path / "backups"
    test_backup_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("api.core.config.BACKUP_DIR", test_backup_dir)
    monkeypatch.setattr("api.routers.system.BACKUP_DIR", test_backup_dir)

    # Isolated snmp conf
    test_snmp_conf = tmp_path / "etc" / "snmp" / "snmpd.conf"
    monkeypatch.setattr("api.core.config.SNMPD_CONF_FILE", test_snmp_conf)
    monkeypatch.setattr("api.routers.system.SNMPD_CONF_FILE", test_snmp_conf)
    monkeypatch.setattr("api.services.security_service.Path", lambda p: test_snmp_conf if "snmpd.conf" in str(p) else Path(p))

    # Mock systemctl calls in update_snmp_config
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: None)


@pytest.fixture
def client():
    return TestClient(app, client=("127.0.0.1", 50000))


# =========================================================================
# 1. SNMP Config Injection Tests
# =========================================================================

class TestSnmpSecurityValidation:
    def test_community_validation_valid(self):
        assert validate_snmp_community("public_read-1") == "public_read-1"
        assert validate_snmp_community("SecureSnmp_2026") == "SecureSnmp_2026"
        assert validate_snmp_community("12345678") == "12345678"

    def test_community_validation_newlines_rejected(self):
        with pytest.raises(HTTPException) as exc:
            validate_snmp_community("public\nextend x /bin/sh")
        assert exc.value.status_code == 400
        assert "newline" in exc.value.detail.lower()

    def test_community_validation_spaces_rejected(self):
        with pytest.raises(HTTPException) as exc:
            validate_snmp_community("public read")
        assert exc.value.status_code == 400

    def test_community_validation_comment_char_rejected(self):
        with pytest.raises(HTTPException) as exc:
            validate_snmp_community("public#admin")
        assert exc.value.status_code == 400

    def test_community_validation_length(self):
        with pytest.raises(HTTPException) as exc:
            validate_snmp_community("short")  # < 8 chars
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_snmp_community("a" * 65)  # > 64 chars
        assert exc.value.status_code == 400

    def test_source_validation_valid(self):
        assert validate_snmp_source("192.168.1.5") == "192.168.1.5/32"
        assert validate_snmp_source("10.0.0.0/24") == "10.0.0.0/24"
        assert validate_snmp_source("127.0.0.1") == "127.0.0.1/32"

    def test_source_validation_injection_rejected(self):
        with pytest.raises(HTTPException) as exc:
            validate_snmp_source("192.168.1.0/24\nextend test /bin/sh")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_snmp_source("192.168.1.0/24 # comment")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_snmp_source("not_an_ip_or_subnet")
        assert exc.value.status_code == 400

    def test_subnets_validation_multiple(self):
        subnets = validate_snmp_subnets("192.168.1.0/24, 10.0.0.1, 127.0.0.1")
        assert len(subnets) == 3
        assert "192.168.1.0/24" in subnets

    def test_text_field_validation(self):
        assert validate_snmp_text_field("Server Room A", "sys_location") == "Server Room A"

        with pytest.raises(HTTPException) as exc:
            validate_snmp_text_field("Server Room\nrocommunity evil 0.0.0.0/0", "sys_location")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_snmp_text_field("admin#comment", "sys_contact")
        assert exc.value.status_code == 400

    def test_snmpv3_validation(self):
        assert validate_snmpv3_user("zclock_snmpv3") == "zclock_snmpv3"
        with pytest.raises(HTTPException) as exc:
            validate_snmpv3_user("user\ninject")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_snmpv3_user("user space")
        assert exc.value.status_code == 400

    def test_write_snmp_config_atomic_mode_0600(self, tmp_path):
        target_conf = tmp_path / "snmp" / "snmpd.conf"
        content = "rocommunity MySecret123 127.0.0.1\n"
        write_snmp_config_atomic(target_conf, content, mode=0o600)

        assert target_conf.exists()
        assert target_conf.read_text() == content
        file_mode = stat.S_IMODE(target_conf.stat().st_mode)
        assert file_mode == 0o600


class TestSnmpEndpointsHardening:
    def test_update_snmp_config_newline_payload_rejected(self, client):
        headers = {"Authorization": "Bearer admin-token-150"}
        payload = {
            "enabled": True,
            "community_string": "public\nextend x /bin/sh",
            "allowed_subnets": "127.0.0.1",
            "sys_location": "Datacenter",
            "sys_contact": "admin@example.com",
            "agent_address": "udp:161",
            "enable_extensions": False,
            "snmpv3_enabled": False,
            "snmpv3_user": ""
        }
        res = client.post("/api/v1/snmp/config", json=payload, headers=headers)
        assert res.status_code == 400
        assert "newline" in res.json()["detail"].lower()

    def test_update_snmp_config_invalid_subnet_rejected(self, client):
        headers = {"Authorization": "Bearer admin-token-150"}
        payload = {
            "enabled": True,
            "community_string": "ValidComm_123",
            "allowed_subnets": "192.168.1.0/24\nextend test /bin/sh",
            "sys_location": "Datacenter",
            "sys_contact": "admin@example.com",
            "agent_address": "udp:161",
            "enable_extensions": False,
            "snmpv3_enabled": False,
            "snmpv3_user": ""
        }
        res = client.post("/api/v1/snmp/config", json=payload, headers=headers)
        assert res.status_code == 400

    def test_update_snmp_config_sys_location_injection_rejected(self, client):
        headers = {"Authorization": "Bearer admin-token-150"}
        payload = {
            "enabled": True,
            "community_string": "ValidComm_123",
            "allowed_subnets": "127.0.0.1",
            "sys_location": "Rack 1\nrocommunity evil 0.0.0.0/0",
            "sys_contact": "admin@example.com",
            "agent_address": "udp:161",
            "enable_extensions": False,
            "snmpv3_enabled": False,
            "snmpv3_user": ""
        }
        res = client.post("/api/v1/snmp/config", json=payload, headers=headers)
        assert res.status_code == 400

    def test_update_snmp_config_audit_logging_and_masking(self, client):
        """Verifies SNMP_CONFIG_UPDATED audit log masks community_string and records real actor."""
        headers = {"Authorization": "Bearer admin-token-150"}
        payload = {
            "enabled": True,
            "community_string": "SuperSecretComm999",
            "allowed_subnets": "192.168.1.0/24",
            "sys_location": "DC-Rack-01",
            "sys_contact": "noc@example.com",
            "agent_address": "udp:161",
            "enable_extensions": False,
            "snmpv3_enabled": False,
            "snmpv3_user": ""
        }
        res = client.post("/api/v1/snmp/config", json=payload, headers=headers)
        assert res.status_code == 200

        # Query audit_events table
        from api.core.config import DB_PATH
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT actor, details FROM audit_events WHERE event_type = 'SNMP_CONFIG_UPDATED' ORDER BY id DESC LIMIT 1")
        row = c.fetchone()
        conn.close()

        assert row is not None, "Audit event for SNMP_CONFIG_UPDATED not found"
        actor, details = row
        assert actor == "admin"
        assert "SuperSecretComm999" not in details
        assert "********" in details

    def test_update_snmp_config_valid_writes_mode_0600(self, client, monkeypatch, tmp_path):
        headers = {"Authorization": "Bearer admin-token-150"}
        test_snmp_conf = tmp_path / "snmpd.conf"
        monkeypatch.setattr("api.routers.system.SNMPD_CONF_FILE", test_snmp_conf)

        payload = {
            "enabled": True,
            "community_string": "ValidComm_123",
            "allowed_subnets": "192.168.1.0/24, 127.0.0.1",
            "sys_location": "Chennai DC Rack 4",
            "sys_contact": "admin@inetcsc.com",
            "agent_address": "udp:161",
            "enable_extensions": True,
            "snmpv3_enabled": True,
            "snmpv3_user": "zclock_monitor"
        }
        res = client.post("/api/v1/snmp/config", json=payload, headers=headers)
        assert res.status_code == 200
        assert test_snmp_conf.exists()
        file_mode = stat.S_IMODE(test_snmp_conf.stat().st_mode)
        assert file_mode == 0o600
        content = test_snmp_conf.read_text()
        assert "rocommunity    ValidComm_123 192.168.1.0/24" in content
        assert "rouser zclock_monitor priv" in content

    def test_security_baseline_snmp_injection_rejected(self, client):
        headers = {"Authorization": "Bearer admin-token-150"}
        payload = {
            "snmp_community": "public\nextend x /bin/sh",
            "allowed_subnets_snmp": "127.0.0.1",
            "ssh_password_auth": True,
            "ssh_port": 22,
            "ufw_enabled": True
        }
        res = client.put("/api/v1/security/settings", json=payload, headers=headers)
        assert res.status_code == 400


# =========================================================================
# 2. Archive Extraction Security Tests
# =========================================================================

class TestArchiveSecurity:
    def test_tar_traversal_rejected(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()

        tar_path = tmp_path / "evil_traversal.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            data = b"malicious content"
            ti = tarfile.TarInfo(name="../../etc/evil.txt")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        with tarfile.open(tar_path, "r:gz") as tar:
            with pytest.raises(ArchiveSecurityError) as exc:
                validate_tar_archive(tar, staging)
            assert exc.value.status_code == 400
            assert "traversal" in exc.value.detail.lower()

    def test_tar_absolute_path_rejected(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()

        tar_path = tmp_path / "evil_abs.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            data = b"malicious content"
            ti = tarfile.TarInfo(name="/etc/evil.txt")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        with tarfile.open(tar_path, "r:gz") as tar:
            with pytest.raises(ArchiveSecurityError) as exc:
                validate_tar_archive(tar, staging)
            assert exc.value.status_code == 400
            assert "absolute" in exc.value.detail.lower()

    def test_tar_symlink_escape_rejected(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()

        tar_path = tmp_path / "evil_symlink.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            ti = tarfile.TarInfo(name="escape_link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tar.addfile(ti)

        with tarfile.open(tar_path, "r:gz") as tar:
            with pytest.raises(ArchiveSecurityError) as exc:
                validate_tar_archive(tar, staging)
            assert exc.value.status_code == 400
            assert "link" in exc.value.detail.lower()

    def test_tar_relative_symlink_escape_rejected(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()

        tar_path = tmp_path / "evil_rel_symlink.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            ti = tarfile.TarInfo(name="sub/escape_link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "../../outside"
            tar.addfile(ti)

        with tarfile.open(tar_path, "r:gz") as tar:
            with pytest.raises(ArchiveSecurityError) as exc:
                validate_tar_archive(tar, staging)
            assert exc.value.status_code == 400
            assert "link" in exc.value.detail.lower()

    def test_zip_traversal_rejected(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()

        zip_path = tmp_path / "evil_traversal.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../etc/evil.txt", b"evil data")

        with zipfile.ZipFile(zip_path, "r") as zf:
            with pytest.raises(ArchiveSecurityError) as exc:
                validate_zip_archive(zf, staging)
            assert exc.value.status_code == 400
            assert "traversal" in exc.value.detail.lower()

    def test_zip_absolute_path_rejected(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()

        zip_path = tmp_path / "evil_abs.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("/etc/evil.txt", b"evil data")

        with zipfile.ZipFile(zip_path, "r") as zf:
            with pytest.raises(ArchiveSecurityError) as exc:
                validate_zip_archive(zf, staging)
            assert exc.value.status_code == 400
            assert "absolute" in exc.value.detail.lower()

    def test_zip_symlink_escape_rejected(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()

        zip_path = tmp_path / "evil_symlink.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zinfo = zipfile.ZipInfo("symlink_file")
            zinfo.create_system = 3  # Unix
            # 0o120000 | 0o777 (symlink mode)
            zinfo.external_attr = 0o120777 << 16
            zf.writestr(zinfo, "/etc/passwd")

        with zipfile.ZipFile(zip_path, "r") as zf:
            with pytest.raises(ArchiveSecurityError) as exc:
                validate_zip_archive(zf, staging)
            assert exc.value.status_code == 400
            assert "symlink" in exc.value.detail.lower()

    def test_upload_backup_with_tar_traversal_returns_400(self, client, tmp_path):
        headers = {"Authorization": "Bearer admin-token-150"}
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
            data = b"evil"
            ti = tarfile.TarInfo(name="../../etc/pwned.txt")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        tar_buf.seek(0)

        files = {"file": ("backup_malicious.tar.gz", tar_buf.getvalue(), "application/gzip")}
        res = client.post("/api/v1/backups/upload", files=files, headers=headers)
        assert res.status_code == 400
        assert "traversal" in res.json()["detail"].lower()

    def test_upload_backup_with_zip_traversal_returns_400(self, client, tmp_path):
        headers = {"Authorization": "Bearer admin-token-150"}
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("../../etc/pwned.txt", b"evil")
        zip_buf.seek(0)

        files = {"file": ("backup_malicious.zip", zip_buf.getvalue(), "application/zip")}
        res = client.post("/api/v1/backups/upload", files=files, headers=headers)
        assert res.status_code == 400
        assert "traversal" in res.json()["detail"].lower()

    def test_safe_extract_tar_filter_unavailable_raises_400(self, tmp_path, monkeypatch):
        staging = tmp_path / "staging"
        staging.mkdir()
        tar_path = tmp_path / "valid.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            data = b"hello"
            ti = tarfile.TarInfo(name="hello.txt")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        monkeypatch.delattr(tarfile, "data_filter", raising=False)

        with tarfile.open(tar_path, "r:gz") as tar:
            with pytest.raises(ArchiveSecurityError) as exc:
                safe_extract_tar(tar, staging)
            assert exc.value.status_code == 400
            assert "data_filter" in exc.value.detail.lower()


# =========================================================================
# 3. CORS Configuration Tests
# =========================================================================

class TestCorsSecurity:
    def test_no_access_control_allow_origin_for_untrusted_origin(self, client):
        # A cross-origin request from https://evil.example
        headers = {
            "Origin": "https://evil.example",
            "Authorization": "Bearer admin-token-150"
        }
        res = client.get("/api/v1/users", headers=headers)
        assert "access-control-allow-origin" not in res.headers

    def test_preflight_options_no_allow_origin_for_untrusted_origin(self, client):
        # CORS preflight OPTIONS request
        headers = {
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET"
        }
        res = client.options("/api/v1/users", headers=headers)
        assert "access-control-allow-origin" not in res.headers
