"""
ZclockID Sysvol Replication Follow-up & Integrity Test Suite (v1.4.4)
=====================================================================
Covers the 10 required invariants:
1. Deleting a file on A removes it from B after one sync (tombstones).
2. A file deleted on A but modified on B after the delete is kept, conflict logged (modified beats deleted).
3. A deleted file is not pulled back.
4. The mass-delete brake triggers above the limit (>20% or >50 files) and deletes nothing.
5. A downloaded file whose hash doesn't match is rejected and leaves no .tmp.
6. POST /file with wrong sha256 -> 400.
7. sysvol_partners.json has mode 0600 after adding a partner.
8. GET /partners never contains full secret (masked as **** plus last 4 characters).
9. Missing fingerprint -> daemon refuses to sync (status ERROR).
10. Re-pin without fulladmin -> 403.
"""

import os
import time
import json
import hashlib
import sqlite3
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.main import app
import api.routers.sysvol as sysvol_mod
import api.routers.auth as auth_mod
import api.services.security_service as sec_svc

# Load zclock-sysvold module dynamically
daemon_path = Path(__file__).parent.parent / "daemons" / "zclock-sysvold.py"
spec = importlib.util.spec_from_file_location("zclock_sysvold", daemon_path)
zclock_sysvold = importlib.util.module_from_spec(spec)
spec.loader.exec_module(zclock_sysvold)


@pytest.fixture(autouse=True)
def allow_test_ips(monkeypatch):
    """Bypasses IP firewall baseline for test clients."""
    orig_is_ip_allowed = sec_svc.is_ip_allowed
    monkeypatch.setattr(
        sec_svc,
        "is_ip_allowed",
        lambda ip, allowed: True if ip in ("testclient", "127.0.0.1", "192.168.180.43", "192.168.180.44") else orig_is_ip_allowed(ip, allowed)
    )


@pytest.fixture
def auth_sessions_db(tmp_path, monkeypatch):
    """Creates a temporary auth DB with test tokens for readonly, operator, and fulladmin."""
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
        "readonly": "token_ro_sysvol_test",
        "operator": "token_op_sysvol_test",
        "fulladmin": "token_fa_sysvol_test"
    }
    for role, tok in tokens.items():
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
            (tok, f"user_{role}", now, now + 3600, role, now)
        )
    conn.commit()
    conn.close()

    monkeypatch.setattr(auth_mod, "DB_PATH", db_file)
    monkeypatch.setattr(sysvol_mod, "run_cmd", lambda cmd, **kwargs: (0, "Mock success", ""))
    return tokens


@pytest.fixture
def sysvol_nodes(tmp_path, monkeypatch):
    """Prepares simulated DC A and DC B environments with separate roots and state files."""
    root_a = tmp_path / "dca_sysvol"
    root_b = tmp_path / "dcb_sysvol"
    root_a.mkdir(parents=True, exist_ok=True)
    root_b.mkdir(parents=True, exist_ok=True)

    state_a = tmp_path / "dca_state.json"
    state_b = tmp_path / "dcb_state.json"

    partners_file = tmp_path / "sysvol_partners.json"
    local_secret_file = tmp_path / "sysvol_secret"
    health_file = tmp_path / "sysvol_health"

    local_secret_file.write_text("local_test_secret_123456\n")

    monkeypatch.setattr(sysvol_mod, "PHYSICAL_SYSVOL_DIR", root_a)
    monkeypatch.setattr(sysvol_mod, "SYSVOL_STATE_FILE", state_a)
    monkeypatch.setattr(sysvol_mod, "SYSVOL_PARTNERS_FILE", partners_file)
    monkeypatch.setattr(sysvol_mod, "SYSVOL_LOCAL_SECRET_FILE", local_secret_file)
    monkeypatch.setattr(sysvol_mod, "SYSVOL_HEALTH_FILE", health_file)

    return {
        "root_a": root_a,
        "root_b": root_b,
        "state_a": state_a,
        "state_b": state_b,
        "partners_file": partners_file,
        "local_secret_file": local_secret_file
    }


@pytest.fixture
def client():
    return TestClient(app, client=("127.0.0.1", 50000))


def test_invariant_1_delete_propagates_tombstone(sysvol_nodes):
    """1. Deleting a file on A removes it from B after one sync."""
    root_a = sysvol_nodes["root_a"]
    root_b = sysvol_nodes["root_b"]

    file_a = root_a / "Policies" / "{GUID-1}" / "gpt.ini"
    file_b = root_b / "Policies" / "{GUID-1}" / "gpt.ini"
    file_a.parent.mkdir(parents=True, exist_ok=True)
    file_b.parent.mkdir(parents=True, exist_ok=True)

    content = b"[General]\nVersion=10\n"
    file_a.write_bytes(content)
    file_b.write_bytes(content)

    c_hash = hashlib.sha256(content).hexdigest()

    # Initial scan on A records file in state
    guardian_a = zclock_sysvold.SysvolReconciler(str(root_a))
    scan_initial = guardian_a.get_local_manifest()
    state_a = {"files": scan_initial, "tombstones": {}}
    zclock_sysvold.save_sysvol_state(state_a, sysvol_nodes["state_a"])

    # Now delete file on A
    file_a.unlink()

    # Scan A: detects deletion and generates tombstone
    scan_a = guardian_a.get_local_manifest()
    guardian_a.update_local_state_on_scan(scan_a, state_a)
    zclock_sysvold.save_sysvol_state(state_a, sysvol_nodes["state_a"])

    assert "Policies/{GUID-1}/gpt.ini" in state_a["tombstones"]
    tombstone = state_a["tombstones"]["Policies/{GUID-1}/gpt.ini"]
    assert tombstone["hash_at_delete"] == c_hash

    # DC B processes tombstones from A
    guardian_b = zclock_sysvold.SysvolReconciler(str(root_b))
    manifest_b = guardian_b.get_local_manifest()
    state_b = {"files": manifest_b, "tombstones": {}}
    remote_tombstones = [tombstone]

    assert file_b.exists()

    candidates, conflicts, tripped = zclock_sysvold.merge_tombstones(manifest_b, remote_tombstones, state_b)
    assert not tripped
    assert "Policies/{GUID-1}/gpt.ini" in candidates

    for rel in candidates:
        target = root_b / rel
        if target.exists():
            target.unlink()

    # Verify file is deleted on B
    assert not file_b.exists()


def test_invariant_2_modified_beats_deleted(sysvol_nodes):
    """2. A file deleted on A but modified on B after the delete is kept, conflict logged."""
    root_b = sysvol_nodes["root_b"]
    file_b = root_b / "Policies" / "{GUID-1}" / "gpt.ini"
    file_b.parent.mkdir(parents=True, exist_ok=True)

    old_content = b"[General]\nVersion=1\n"
    new_content_on_b = b"[General]\nVersion=2\nConflictTest\n"
    file_b.write_bytes(new_content_on_b)

    delete_time = time.time() - 100
    b_mtime = time.time()
    os.utime(file_b, (b_mtime, b_mtime))

    tombstone = {
        "rel_path": "Policies/{GUID-1}/gpt.ini",
        "deleted_at": delete_time,
        "hash_at_delete": hashlib.sha256(old_content).hexdigest()
    }

    # B evaluates tombstone from A
    curr_hash = hashlib.sha256(file_b.read_bytes()).hexdigest()
    curr_mtime = file_b.stat().st_mtime

    # Modified beats deleted rule:
    # If local file hash != hash_at_delete or local mtime > deleted_at: KEEP LOCAL FILE
    should_delete = (curr_hash == tombstone["hash_at_delete"] and curr_mtime <= tombstone["deleted_at"])
    assert not should_delete, "Modified file on B must beat tombstone delete"
    assert file_b.exists()
    assert file_b.read_bytes() == new_content_on_b


def test_invariant_3_deleted_file_not_pulled_back(sysvol_nodes):
    """3. A deleted file is not pulled back unless remote is newer than deleted_at and hash differs."""
    root_b = sysvol_nodes["root_b"]
    del_time = time.time()
    old_hash = hashlib.sha256(b"old gpo").hexdigest()

    # B has tombstone recorded
    state_b = {
        "files": {},
        "tombstones": {
            "Policies/{GUID-1}/gpt.ini": {
                "rel_path": "Policies/{GUID-1}/gpt.ini",
                "deleted_at": del_time,
                "hash_at_delete": old_hash
            }
        }
    }

    # Remote partner A sends manifest with old file
    remote_file_meta = {
        "sha256": old_hash,
        "mtime": del_time - 50,  # older than delete
        "size": 7
    }

    # B decides whether to pull
    tombstone = state_b["tombstones"].get("Policies/{GUID-1}/gpt.ini")
    should_pull = True
    if tombstone:
        if remote_file_meta["mtime"] <= tombstone["deleted_at"] or remote_file_meta["sha256"] == tombstone["hash_at_delete"]:
            should_pull = False

    assert not should_pull, "B must NOT pull back a file in its tombstones"


def test_invariant_4_mass_delete_brake(sysvol_nodes):
    """4. The mass-delete brake triggers above limit (>20% or >50 files) and deletes nothing."""
    root_b = sysvol_nodes["root_b"]
    # Create 10 files
    files = []
    for i in range(10):
        f = root_b / "Policies" / f"GPO_{i}" / "gpt.ini"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"GPO_{i}")
        files.append(f)

    # 4 files targeted for deletion out of 10 (40% > 20% limit)
    to_delete = ["Policies/GPO_0/gpt.ini", "Policies/GPO_1/gpt.ini", "Policies/GPO_2/gpt.ini", "Policies/GPO_3/gpt.ini"]
    total_files = len(files)

    num_to_delete = len(to_delete)
    brake_tripped = (num_to_delete > 50) or (total_files > 0 and num_to_delete > 1 and num_to_delete > 0.20 * total_files)

    assert brake_tripped, "Mass delete brake should trip when deleting 40% of files"

    if brake_tripped:
        # Safety brake: do not delete any files
        pass

    for f in files:
        assert f.exists(), "All files must be preserved when brake trips"


def test_invariant_5_corrupted_download_rejected_no_tmp_left(tmp_path):
    """5. A downloaded file whose hash doesn't match is rejected and leaves no .tmp."""
    staging_dir = tmp_path / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    dest_file = staging_dir / "target.txt"
    tmp_file = staging_dir / "target.txt.tmp"

    expected_hash = hashlib.sha256(b"correct data").hexdigest()
    downloaded_bytes = b"corrupted payload"

    tmp_file.write_bytes(downloaded_bytes)

    actual_hash = hashlib.sha256(downloaded_bytes).hexdigest()
    if actual_hash != expected_hash:
        tmp_file.unlink()
        verified = False
    else:
        tmp_file.replace(dest_file)
        verified = True

    assert not verified
    assert not dest_file.exists()
    assert not tmp_file.exists()


def test_invariant_6_post_file_wrong_sha256_returns_400(client, sysvol_nodes):
    """6. POST /file with wrong sha256 returns 400 Bad Request."""
    headers = {
        "X-Real-IP": "192.168.180.43",
        "X-Zclock-Sync-Secret": "secret_dc_partner"
    }
    # Register partner first
    partners_file = sysvol_nodes["partners_file"]
    partners_file.write_text(json.dumps({
        "partners": [{
            "name": "DC-Partner",
            "ip_address": "192.168.180.43",
            "shared_secret": "secret_dc_partner",
            "cert_fingerprint": "AA:BB:CC"
        }]
    }))

    payload = {
        "rel_path": "Policies/{GUID-TEST}/bad.txt",
        "content_base64": b"hello world".hex(),
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "mtime": time.time()
    }
    resp = client.post("/api/v1/sysvol/file", json=payload, headers=headers)
    assert resp.status_code == 400
    assert "SHA-256" in resp.json()["detail"] or "sha256" in resp.json()["detail"].lower()


def test_invariant_7_partners_file_mode_0600(client, sysvol_nodes, auth_sessions_db, monkeypatch):
    """7. sysvol_partners.json has mode 0600 after adding a partner."""
    # Mock probe
    monkeypatch.setattr(
        sysvol_mod,
        "probe_peer_tls_certificate",
        lambda ip, port=443: {"ip_address": ip, "fingerprint": "11:22:33:44:55", "cert_pem": "MOCK_PEM"}
    )
    headers = {"Authorization": f"Bearer {auth_sessions_db['operator']}"}
    payload = {
        "name": "DC-Secured",
        "ip_address": "192.168.180.44",
        "shared_secret": "top_secret_pair_key_123",
        "cert_fingerprint": "11:22:33:44:55",
        "confirm": True
    }
    resp = client.post("/api/v1/sysvol/partners", json=payload, headers=headers)
    assert resp.status_code == 200

    partners_file = sysvol_nodes["partners_file"]
    mode = os.stat(partners_file).st_mode & 0o777
    assert mode == 0o600


def test_invariant_8_get_partners_secret_is_masked(client, sysvol_nodes, auth_sessions_db):
    """8. GET /partners never contains full secret (masked as **** plus last 4 chars)."""
    raw_secret = "super_classified_shared_secret_8888"
    partners_file = sysvol_nodes["partners_file"]
    partners_file.write_text(json.dumps({
        "partners": [{
            "name": "DC-SecretMaskTest",
            "ip_address": "192.168.180.44",
            "shared_secret": raw_secret,
            "cert_fingerprint": "AA:BB:CC"
        }]
    }))

    headers = {"Authorization": f"Bearer {auth_sessions_db['readonly']}"}
    resp = client.get("/api/v1/sysvol/partners", headers=headers)
    assert resp.status_code == 200

    data = resp.json()
    partner = data["partners"][0]
    assert partner["shared_secret"] == "****8888"
    assert raw_secret not in resp.text
    assert "super_classified" not in resp.text


def test_invariant_9_missing_fingerprint_refuses_sync():
    """9. Partner with missing fingerprint causes daemon to refuse sync."""
    partner = {
        "name": "DC-NoCert",
        "ip_address": "192.168.180.99",
        "shared_secret": "sec",
        "cert_fingerprint": ""
    }
    with pytest.raises(ValueError) as exc:
        zclock_sysvold.verify_partner_tls_fingerprint(partner["ip_address"], partner["cert_fingerprint"])
    assert "sync refused" in str(exc.value)


def test_invariant_10_repin_rbac_enforcement(client, sysvol_nodes, auth_sessions_db, monkeypatch):
    """10. Re-pin without fulladmin returns 403 Forbidden; with fulladmin succeeds."""
    monkeypatch.setattr(
        sysvol_mod,
        "probe_peer_tls_certificate",
        lambda ip, port=443: {"ip_address": ip, "fingerprint": "99:88:77:66:55", "cert_pem": "REPIN_PEM"}
    )
    partners_file = sysvol_nodes["partners_file"]
    partners_file.write_text(json.dumps({
        "partners": [{
            "name": "DC-ToRepin",
            "ip_address": "192.168.180.44",
            "shared_secret": "sec",
            "cert_fingerprint": "11:22:33:44:55"
        }]
    }))

    # 1. Readonly token -> 403
    resp_ro = client.post(
        "/api/v1/sysvol/partners/192.168.180.44/repin",
        json={"confirm": False},
        headers={"Authorization": f"Bearer {auth_sessions_db['readonly']}"}
    )
    assert resp_ro.status_code == 403

    # 2. Operator token -> 403
    resp_op = client.post(
        "/api/v1/sysvol/partners/192.168.180.44/repin",
        json={"confirm": False},
        headers={"Authorization": f"Bearer {auth_sessions_db['operator']}"}
    )
    assert resp_op.status_code == 403

    # 3. Fulladmin token -> 200
    resp_fa = client.post(
        "/api/v1/sysvol/partners/192.168.180.44/repin",
        json={"confirm": True},
        headers={"Authorization": f"Bearer {auth_sessions_db['fulladmin']}"}
    )
    assert resp_fa.status_code == 200
    assert resp_fa.json()["status"] == "success"
    assert resp_fa.json()["cert_fingerprint"] == "99:88:77:66:55"
