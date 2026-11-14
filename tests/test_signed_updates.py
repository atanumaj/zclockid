"""
Unit and integration tests for ZclockID signed repository and update verification (v1.4.0).
Verifies:
1. Insecure bypass flags appear nowhere in the codebase, installer scripts, or documentation.
2. Good GPG detached signatures are accepted.
3. Unsigned update packages are rejected with 400.
4. Update packages signed with an untrusted/different key are rejected with 400.
5. Tampered .deb packages (single byte flipped) are rejected with 400.
6. Version downgrades are hard errors unless explicit allow_downgrade=true is set by fulladmin.
7. Update downloads strictly enforce HTTPS.
"""

import os
import re
import time
import sqlite3
import shutil
import tempfile
import subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.main import app
import api.main as main_mod
import api.core.config as config
import api.routers.auth as auth_mod
import api.routers.system as sys_mod
from api.routers.system import verify_package_signature, is_downgrade_version
import api.services.security_service as sec_svc
from api.db.init_db import init_db

client = TestClient(app, client=("127.0.0.1", 50000), base_url="http://127.0.0.1")

ADMIN_HEADERS = {"Authorization": "Bearer tok_admin"}
OPERATOR_HEADERS = {"Authorization": "Bearer tok_operator"}


@pytest.fixture(autouse=True)
def allow_testclient_in_tests(monkeypatch, tmp_path_factory):
    """Allows testclient / 127.0.0.1 in the security baseline firewall check and sets up clean SQLite DB."""
    orig_is_ip_allowed = sec_svc.is_ip_allowed
    allow_fn = lambda ip, allowed: True if ip in ("testclient", "127.0.0.1") else orig_is_ip_allowed(ip, allowed)
    monkeypatch.setattr(sec_svc, "is_ip_allowed", allow_fn)
    monkeypatch.setattr(main_mod, "is_ip_allowed", allow_fn)

    test_db = tmp_path_factory.mktemp("db") / "test_zclockid.db"
    init_db(test_db)
    import api.db.init_db as init_db_mod
    monkeypatch.setattr(init_db_mod, "DB_PATH", test_db)
    monkeypatch.setattr(config, "DB_PATH", test_db)
    monkeypatch.setattr(sys_mod, "DB_PATH", test_db)
    monkeypatch.setattr(auth_mod, "DB_PATH", test_db)

    # Insert test sessions for fulladmin and operator
    now = time.time()
    conn = sqlite3.connect(test_db)
    conn.execute(
        "INSERT INTO sessions (token, username, role, created_at, expires_at, last_active) VALUES (?, ?, ?, ?, ?, ?)",
        ("tok_admin", "admin", "fulladmin", now, now + 3600, now)
    )
    conn.execute(
        "INSERT INTO sessions (token, username, role, created_at, expires_at, last_active) VALUES (?, ?, ?, ?, ?, ?)",
        ("tok_operator", "op_user", "operator", now, now + 3600, now)
    )
    conn.commit()
    conn.close()


@pytest.fixture(scope="session")
def throwaway_gpg_keys():
    """
    Generates two disposable GPG keypairs in short temp directories in /tmp
    (avoiding UNIX socket length limits on macOS):
    - Key A: The trusted repository signing key.
    - Key B: An untrusted / rogue key.
    Exports Key A's public key to a binary keyring (.gpg) matching archive format.
    """
    base_tmp = Path(tempfile.mkdtemp(prefix="zgpg_", dir="/tmp"))
    homedir_a = base_tmp / "a"
    homedir_b = base_tmp / "b"
    homedir_a.mkdir(mode=0o700)
    homedir_b.mkdir(mode=0o700)

    def _generate_key(homedir, name, email):
        batch_file = homedir / "keygen.batch"
        batch_file.write_text(f"""%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: {name}
Name-Email: {email}
Expire-Date: 0
%commit
""")
        res = subprocess.run(
            ["gpg", "--homedir", str(homedir), "--batch", "--generate-key", str(batch_file)],
            capture_output=True,
            text=True
        )
        assert res.returncode == 0, f"Failed to generate GPG key: {res.stderr}"

    _generate_key(homedir_a, "ZclockID Trusted Test Signer", "security@test.zclockid.local")
    _generate_key(homedir_b, "Untrusted Attacker Key", "attacker@evil.local")

    # Export Key A public keyring
    keyring_a = base_tmp / "trusted-keyring.gpg"
    res = subprocess.run(
        ["gpg", "--homedir", str(homedir_a), "--export", "--output", str(keyring_a)],
        capture_output=True
    )
    assert res.returncode == 0, "Failed to export Key A keyring"

    yield {
        "homedir_a": homedir_a,
        "homedir_b": homedir_b,
        "trusted_keyring": keyring_a,
        "tmp_dir": base_tmp
    }

    # Cleanup
    shutil.rmtree(base_tmp, ignore_errors=True)


def _create_sample_deb_file(dest_path: Path, package_name: str = "zclockid", version: str = "1.4.0"):
    """Creates a sample dummy .deb file for cryptographic testing."""
    content = f"DUMMY_DEB_ARCHIVE_{package_name}_{version}\n" + ("x" * 2048)
    dest_path.write_text(content)


def _sign_file(homedir: Path, target_file: Path, sig_dest: Path):
    """Generates a detached OpenPGP binary signature using the key in homedir."""
    res = subprocess.run(
        ["gpg", "--homedir", str(homedir), "--batch", "--yes", "--detach-sign", "-o", str(sig_dest), str(target_file)],
        capture_output=True,
        text=True
    )
    assert res.returncode == 0, f"Signing failed: {res.stderr}"


# ----------------- Tests -----------------

def test_repo_strictly_contains_no_trusted_yes():
    """Verify that forbidden bypass string appears nowhere in repo code, installer scripts, or docs."""
    repo_root = Path(__file__).resolve().parent.parent
    violations = []

    # Excluded directories
    ignore_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", "build", "dist", "var", "node_modules"}
    needle = "trusted" + "=yes"
    pattern = re.compile(r"trusted\s*=\s*yes", re.IGNORECASE)

    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            # Skip test itself and binary packages, archives, images, git databases
            if f == "test_signed_updates.py":
                continue
            if f.endswith((".deb", ".gz", ".tar", ".png", ".jpg", ".gpg", ".db", ".iso", ".pyc")):
                continue
            fpath = Path(root) / f
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                if pattern.search(content):
                    violations.append(str(fpath.relative_to(repo_root)))
            except Exception:
                continue

    assert len(violations) == 0, f"Found insecure '{needle}' references in: {violations}"


def test_signature_verification_good_signature(throwaway_gpg_keys, monkeypatch):
    """Verify that verify_package_signature accepts a good signature from the trusted key."""
    tmp = throwaway_gpg_keys["tmp_dir"] / "test_good"
    tmp.mkdir(exist_ok=True)
    deb = tmp / "package.deb"
    sig = tmp / "package.deb.sig"

    _create_sample_deb_file(deb)
    _sign_file(throwaway_gpg_keys["homedir_a"], deb, sig)

    monkeypatch.setenv("ZCLOCKID_KEYRING_PATH", str(throwaway_gpg_keys["trusted_keyring"]))
    is_valid, msg = verify_package_signature(deb, sig)
    assert is_valid is True, f"Expected valid signature, got error: {msg}"
    assert "good signature" in msg.lower()


def test_signature_verification_wrong_key_rejected(throwaway_gpg_keys, monkeypatch):
    """Verify that verify_package_signature rejects a signature from an untrusted key."""
    tmp = throwaway_gpg_keys["tmp_dir"] / "test_wrong_key"
    tmp.mkdir(exist_ok=True)
    deb = tmp / "package.deb"
    sig = tmp / "package.deb.sig"

    _create_sample_deb_file(deb)
    # Sign with Key B (untrusted)
    _sign_file(throwaway_gpg_keys["homedir_b"], deb, sig)

    monkeypatch.setenv("ZCLOCKID_KEYRING_PATH", str(throwaway_gpg_keys["trusted_keyring"]))
    is_valid, msg = verify_package_signature(deb, sig)
    assert is_valid is False
    assert "no public key" in msg.lower() or "not found" in msg.lower() or "bad" in msg.lower()


def test_signature_verification_tampered_deb_rejected(throwaway_gpg_keys, monkeypatch):
    """Verify that flipping even a single byte in the deb invalidates the signature."""
    tmp = throwaway_gpg_keys["tmp_dir"] / "test_tamper"
    tmp.mkdir(exist_ok=True)
    deb = tmp / "package.deb"
    sig = tmp / "package.deb.sig"

    _create_sample_deb_file(deb)
    _sign_file(throwaway_gpg_keys["homedir_a"], deb, sig)

    # Tamper with the package by flipping one byte
    raw_data = bytearray(deb.read_bytes())
    raw_data[64] ^= 0xFF
    deb.write_bytes(raw_data)

    monkeypatch.setenv("ZCLOCKID_KEYRING_PATH", str(throwaway_gpg_keys["trusted_keyring"]))
    is_valid, msg = verify_package_signature(deb, sig)
    assert is_valid is False
    assert "bad signature" in msg.lower() or "invalid" in msg.lower()


def test_api_upload_unsigned_rejected():
    """Verify that POST /api/v1/system/update/upload rejects an upload without signature with 400."""
    deb_content = b"DUMMY_DEB_DATA" * 100
    files = {
        "package": ("zclockid_1.4.0_all.deb", deb_content, "application/vnd.debian.binary-package")
    }
    res = client.post("/api/v1/system/update/upload", files=files, headers=ADMIN_HEADERS)
    assert res.status_code == 400
    assert "Missing required detached package signature" in res.json()["detail"]


def test_api_upload_tampered_file_rejected(throwaway_gpg_keys, monkeypatch):
    """Verify that POST /api/v1/system/update/upload rejects a tampered .deb with 400."""
    monkeypatch.setenv("ZCLOCKID_KEYRING_PATH", str(throwaway_gpg_keys["trusted_keyring"]))

    tmp = throwaway_gpg_keys["tmp_dir"] / "test_api_tamper"
    tmp.mkdir(exist_ok=True)
    deb = tmp / "package.deb"
    sig = tmp / "package.deb.sig"

    _create_sample_deb_file(deb)
    _sign_file(throwaway_gpg_keys["homedir_a"], deb, sig)

    # Tamper deb
    tampered_bytes = bytearray(deb.read_bytes())
    tampered_bytes[10] ^= 0xFF

    files = {
        "package": ("zclockid_1.4.0_all.deb", bytes(tampered_bytes), "application/vnd.debian.binary-package"),
        "signature": ("zclockid_1.4.0_all.deb.sig", sig.read_bytes(), "application/pgp-signature")
    }
    res = client.post("/api/v1/system/update/upload", files=files, headers=ADMIN_HEADERS)
    assert res.status_code == 400
    assert "signature verification failed" in res.json()["detail"].lower()


def test_api_upload_good_signature_accepted(throwaway_gpg_keys, monkeypatch):
    """Verify that a validly signed deb passes signature verification."""
    monkeypatch.setenv("ZCLOCKID_KEYRING_PATH", str(throwaway_gpg_keys["trusted_keyring"]))

    # Mock dpkg-deb inspection so test can run on any OS
    def mock_run_cmd(cmd, **kwargs):
        if cmd[0] == "dpkg-deb":
            return 0, "Package: zclockid\nVersion: 1.4.0\nArchitecture: all\n", ""
        return 0, "", ""
    monkeypatch.setattr(sys_mod, "run_cmd", mock_run_cmd)

    tmp = throwaway_gpg_keys["tmp_dir"] / "test_api_good"
    tmp.mkdir(exist_ok=True)
    deb = tmp / "package.deb"
    sig = tmp / "package.deb.sig"

    _create_sample_deb_file(deb)
    _sign_file(throwaway_gpg_keys["homedir_a"], deb, sig)

    files = {
        "package": ("zclockid_1.4.0_all.deb", deb.read_bytes(), "application/vnd.debian.binary-package"),
        "signature": ("zclockid_1.4.0_all.deb.sig", sig.read_bytes(), "application/pgp-signature")
    }
    data = {"auto_install": "false"}
    res = client.post("/api/v1/system/update/upload", files=files, data=data, headers=ADMIN_HEADERS)
    assert res.status_code == 200, f"Upload failed: {res.text}"
    res_data = res.json()
    assert res_data["sig_verified"] is True
    assert res_data["version"] == "1.4.0"


def test_downgrade_protection(throwaway_gpg_keys, monkeypatch):
    """Verify that downgrading to an older version is rejected unless explicit allow_downgrade is set by fulladmin."""
    monkeypatch.setenv("ZCLOCKID_KEYRING_PATH", str(throwaway_gpg_keys["trusted_keyring"]))
    monkeypatch.setattr(sys_mod, "get_appliance_version", lambda: "1.4.0")

    def mock_run_cmd(cmd, **kwargs):
        if cmd[0] == "dpkg-deb":
            return 0, "Package: zclockid\nVersion: 1.3.0\nArchitecture: all\n", ""
        return 0, "", ""
    monkeypatch.setattr(sys_mod, "run_cmd", mock_run_cmd)

    tmp = throwaway_gpg_keys["tmp_dir"] / "test_api_downgrade"
    tmp.mkdir(exist_ok=True)
    deb = tmp / "package.deb"
    sig = tmp / "package.deb.sig"
    _create_sample_deb_file(deb)
    _sign_file(throwaway_gpg_keys["homedir_a"], deb, sig)

    files = {
        "package": ("zclockid_1.3.0_all.deb", deb.read_bytes(), "application/vnd.debian.binary-package"),
        "signature": ("zclockid_1.3.0_all.deb.sig", sig.read_bytes(), "application/pgp-signature")
    }

    # 1. Downgrade attempt without allow_downgrade -> 400
    res = client.post("/api/v1/system/update/upload", files=files, data={"allow_downgrade": "false"}, headers=ADMIN_HEADERS)
    assert res.status_code == 400
    assert "downgrade rejected" in res.json()["detail"].lower()

    # 2. Downgrade attempt with allow_downgrade by non-fulladmin (operator) -> 403
    res = client.post("/api/v1/system/update/upload", files=files, data={"allow_downgrade": "true"}, headers=OPERATOR_HEADERS)
    assert res.status_code == 403

    # 3. Downgrade attempt with allow_downgrade by fulladmin -> 200
    res = client.post("/api/v1/system/update/upload", files=files, data={"allow_downgrade": "true", "auto_install": "false"}, headers=ADMIN_HEADERS)
    assert res.status_code == 200


def test_update_install_https_only():
    """Verify that update installation from URL strictly enforces HTTPS and rejects plain HTTP."""
    res = client.post("/api/v1/system/update/install", json={"download_url": "http://insecure.example.com/zclockid.deb"}, headers=ADMIN_HEADERS)
    assert res.status_code == 400
    assert "HTTPS" in res.json()["detail"]


def test_key_rotation_documentation_exists():
    """Verify that docs/KEY_ROTATION.md exists and covers dual keyring rotation runbook."""
    repo_root = Path(__file__).resolve().parent.parent
    key_rot_doc = repo_root / "docs" / "KEY_ROTATION.md"
    assert key_rot_doc.exists(), "docs/KEY_ROTATION.md must exist"
    content = key_rot_doc.read_text(encoding="utf-8")
    assert "Dual-Key Keyring Window" in content
    assert "/usr/share/keyrings/zclockid-archive-keyring.gpg" in content
    assert "Emergency Key Revocation Runbook" in content
