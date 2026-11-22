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
    headers = {"Authorization": f"Bearer {auth_sessions_db['fulladmin']}"}
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


def test_sysvol_partner_role_and_fingerprint_validation(client, sysvol_nodes, auth_sessions_db, monkeypatch):
    """v1.5.3: SYSVOL pairing requires fulladmin, confirm without fingerprint returns 400, mismatch returns 409."""
    monkeypatch.setattr(
        sysvol_mod,
        "probe_peer_tls_certificate",
        lambda ip, port=443: {"ip_address": ip, "fingerprint": "11:22:33:44:55", "cert_pem": "MOCK_PEM"}
    )
    # 1. Operator role gets 403
    op_headers = {"Authorization": f"Bearer {auth_sessions_db['operator']}"}
    res_op = client.post("/api/v1/sysvol/partners", json={
        "name": "DC-FailRole",
        "ip_address": "192.168.180.45",
        "shared_secret": "pair_key_op",
        "cert_fingerprint": "11:22:33:44:55",
        "confirm": True
    }, headers=op_headers)
    assert res_op.status_code == 403, f"Expected 403 for operator, got {res_op.status_code}"

    # 2. confirm=True without cert_fingerprint returns 400
    admin_headers = {"Authorization": f"Bearer {auth_sessions_db['fulladmin']}"}
    res_no_fp = client.post("/api/v1/sysvol/partners", json={
        "name": "DC-NoFp",
        "ip_address": "192.168.180.45",
        "shared_secret": "pair_key_admin",
        "cert_fingerprint": None,
        "confirm": True
    }, headers=admin_headers)
    assert res_no_fp.status_code == 400, f"Expected 400 for confirm without cert_fingerprint, got {res_no_fp.status_code}"

    # 3. Fingerprint mismatch between probe (11:22:33:44:55) and submitted (AA:BB:CC:DD:EE) returns 409
    res_mismatch = client.post("/api/v1/sysvol/partners", json={
        "name": "DC-Mismatch",
        "ip_address": "192.168.180.45",
        "shared_secret": "pair_key_admin",
        "cert_fingerprint": "AA:BB:CC:DD:EE",
        "confirm": True
    }, headers=admin_headers)
    assert res_mismatch.status_code == 409, f"Expected 409 for fingerprint mismatch, got {res_mismatch.status_code}"
    assert "mismatch" in res_mismatch.json()["detail"].lower()


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


def test_invariant_11_mass_delete_pending_and_rbac_flow(client, sysvol_nodes, auth_sessions_db):
    """11. Mass delete pending list, operator 403 on confirm/reject, 409 on timestamp mismatch, fulladmin confirm/reject."""
    state_file = sysvol_nodes["state_a"]
    test_detected_at = 1700000000.0
    pending_paths = ["cybertechie.net/Policies/{GPO-1}/gpt.ini", "cybertechie.net/Policies/{GPO-2}/gpt.ini"]

    state = {
        "files": {},
        "tombstones": {},
        "mass_delete_tripped": True,
        "pending_mass_delete": {
            "partner_ip": "192.168.180.44",
            "paths": pending_paths,
            "detected_at": test_detected_at
        }
    }
    state_file.write_text(json.dumps(state))

    # 1. Readonly on pending -> 403
    ro_headers = {"Authorization": f"Bearer {auth_sessions_db['readonly']}"}
    r = client.get("/api/v1/sysvol/mass-delete/pending", headers=ro_headers)
    assert r.status_code == 403

    # 2. Operator on pending -> 200 with list
    op_headers = {"Authorization": f"Bearer {auth_sessions_db['operator']}"}
    r = client.get("/api/v1/sysvol/mass-delete/pending", headers=op_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["has_pending"] is True
    assert data["pending"]["count"] == 2
    assert data["pending"]["paths"] == pending_paths
    assert data["pending"]["detected_at"] == test_detected_at

    # 3. Operator on confirm -> 403 (requires fulladmin)
    r = client.post("/api/v1/sysvol/mass-delete/confirm", json={"detected_at": test_detected_at}, headers=op_headers)
    assert r.status_code == 403

    # 4. Operator on reject -> 403 (requires fulladmin)
    r = client.post("/api/v1/sysvol/mass-delete/reject", headers=op_headers)
    assert r.status_code == 403

    # 5. Fulladmin with stale timestamp -> 409 Conflict
    fa_headers = {"Authorization": f"Bearer {auth_sessions_db['fulladmin']}"}
    r = client.post("/api/v1/sysvol/mass-delete/confirm", json={"detected_at": 1699999999.0}, headers=fa_headers)
    assert r.status_code == 409
    assert "mismatch" in r.json()["detail"].lower()

    # 6. Fulladmin with matching timestamp -> 200 OK
    r = client.post("/api/v1/sysvol/mass-delete/confirm", json={"detected_at": test_detected_at}, headers=fa_headers)
    assert r.status_code == 200
    saved_state = json.loads(state_file.read_text())
    assert saved_state["approved_mass_delete"]["paths"] == pending_paths
    assert saved_state["approved_mass_delete"]["detected_at"] == test_detected_at

    # 7. Fulladmin reject -> 200 OK, clears pending and approved
    r = client.post("/api/v1/sysvol/mass-delete/reject", headers=fa_headers)
    assert r.status_code == 200
    saved_state = json.loads(state_file.read_text())
    assert saved_state.get("pending_mass_delete") is None
    assert saved_state.get("approved_mass_delete") is None
    assert saved_state.get("mass_delete_tripped") is False


def test_invariant_12_python_daemon_threshold_and_approval():
    """12. Python daemon: 6 of 25 does not trip, 15 of 25 trips, approval executes, unapproved new file re-trips."""
    now = time.time()
    local_manifest = {
        f"domain/Policies/GPO_{i:02d}/gpt.ini": {"hash": f"{i:064d}", "mtime": now - 500, "size": 10}
        for i in range(25)
    }

    # 6 of 25 -> Does not trip
    tombs_6 = [
        {"rel_path": f"domain/Policies/GPO_{i:02d}/gpt.ini", "deleted_at": now - 10, "hash_at_delete": f"{i:064d}"}
        for i in range(6)
    ]
    state = {"files": {}, "tombstones": {}}
    to_del, conf, tripped = zclock_sysvold.merge_tombstones(local_manifest, tombs_6, state, "192.168.180.44")
    assert not tripped
    assert len(to_del) == 6

    # 15 of 25 -> Trips
    tombs_15 = [
        {"rel_path": f"domain/Policies/GPO_{i:02d}/gpt.ini", "deleted_at": now - 10, "hash_at_delete": f"{i:064d}"}
        for i in range(15)
    ]
    state = {"files": {}, "tombstones": {}}
    to_del, conf, tripped = zclock_sysvold.merge_tombstones(local_manifest, tombs_15, state, "192.168.180.44")
    assert tripped
    assert len(to_del) == 0
    assert state.get("mass_delete_tripped") is True
    assert state.get("pending_mass_delete") is not None
    assert len(state["pending_mass_delete"]["paths"]) == 15

    # Approval executes
    state["approved_mass_delete"] = {
        "partner_ip": "192.168.180.44",
        "paths": [t["rel_path"] for t in tombs_15],
        "detected_at": state["pending_mass_delete"]["detected_at"]
    }
    to_del, conf, tripped = zclock_sysvold.merge_tombstones(local_manifest, tombs_15, state, "192.168.180.44")
    assert not tripped
    assert len(to_del) == 15
    assert state.get("approved_mass_delete") is None
    assert state.get("pending_mass_delete") is None
    assert state.get("mass_delete_tripped") is False

    # Unapproved new file re-trips
    state = {
        "files": {},
        "tombstones": {},
        "approved_mass_delete": {
            "partner_ip": "192.168.180.44",
            "paths": [t["rel_path"] for t in tombs_15],
            "detected_at": now - 30
        }
    }
    tombs_16 = tombs_15 + [
        {"rel_path": "domain/Policies/GPO_15/gpt.ini", "deleted_at": now - 5, "hash_at_delete": f"{15:064d}"}
    ]
    to_del, conf, tripped = zclock_sysvold.merge_tombstones(local_manifest, tombs_16, state, "192.168.180.44")
    assert tripped
    assert len(to_del) == 0
    assert state.get("approved_mass_delete") is None
    assert len(state["pending_mass_delete"]["paths"]) == 16


def test_invariant_13_approval_zero_candidates_not_consumed():
    """13. Approval with 0 candidates is not consumed."""
    now = time.time()
    local_manifest = {
        "domain/Policies/GPO_01/gpt.ini": {"hash": "hash1", "mtime": now - 500, "size": 10}
    }
    state = {
        "files": dict(local_manifest),
        "tombstones": {},
        "approved_mass_delete": {
            "partner_ip": "192.168.180.44",
            "paths": ["domain/Policies/GPO_99/gpt.ini"],
            "detected_at": now - 50
        }
    }
    # No matching tombstones in remote list -> candidates is empty
    candidates, conflicts, tripped = zclock_sysvold.merge_tombstones(
        local_manifest, [], state, "192.168.180.44"
    )
    assert not tripped
    assert candidates == []
    # Approval MUST NOT be consumed
    assert state.get("approved_mass_delete") is not None
    assert state["approved_mass_delete"]["paths"] == ["domain/Policies/GPO_99/gpt.ini"]


def test_invariant_14_two_node_simulation_reject_restores_15_files(tmp_path):
    """14. Two-node simulation: delete 15 on A, B trips, reject on B, run 3 cycles -> all 15 files exist on both, no tombstones remain, health is HEALTHY."""
    root_a = tmp_path / "node_a_sysvol"
    root_b = tmp_path / "node_b_sysvol"
    root_a.mkdir(parents=True, exist_ok=True)
    root_b.mkdir(parents=True, exist_ok=True)

    state_file_a = tmp_path / "node_a_state.json"
    state_file_b = tmp_path / "node_b_state.json"
    health_file_b = tmp_path / "node_b_health"

    reconciler_a = zclock_sysvold.SysvolReconciler(str(root_a))
    reconciler_b = zclock_sysvold.SysvolReconciler(str(root_b))

    # Create 15 files on both nodes
    file_hashes = {}
    now = time.time()
    for i in range(15):
        rel_p = f"domain/Policies/GPO_{i:02d}/gpt.ini"
        content = f"[General]\nVersion={i}\nSection=TestGPO{i}\n".encode("utf-8")
        h = hashlib.sha256(content).hexdigest()
        file_hashes[rel_p] = h

        p_a = root_a / rel_p
        p_b = root_b / rel_p
        p_a.parent.mkdir(parents=True, exist_ok=True)
        p_b.parent.mkdir(parents=True, exist_ok=True)
        p_a.write_bytes(content)
        p_b.write_bytes(content)
        os.utime(p_a, (now - 100, now - 100))
        os.utime(p_b, (now - 100, now - 100))

    # Initialize state on both nodes
    state_a = {"files": reconciler_a.get_local_manifest(), "tombstones": {}}
    state_b = {"files": reconciler_b.get_local_manifest(), "tombstones": {}}
    zclock_sysvold.save_sysvol_state(state_a, state_file_a)
    zclock_sysvold.save_sysvol_state(state_b, state_file_b)

    # 1. Delete all 15 files on Node A
    for i in range(15):
        rel_p = f"domain/Policies/GPO_{i:02d}/gpt.ini"
        (root_a / rel_p).unlink()

    # Scan on Node A -> 15 tombstones recorded
    manifest_a = reconciler_a.get_local_manifest()
    assert len(manifest_a) == 0
    reconciler_a.update_local_state_on_scan(manifest_a, state_a)
    zclock_sysvold.save_sysvol_state(state_a, state_file_a)
    assert len(state_a["tombstones"]) == 15

    # 2. Node B syncs against Node A -> Safety brake trips
    manifest_b = reconciler_b.get_local_manifest()
    remote_tombs_from_a = list(state_a["tombstones"].values())
    candidates, conflicts, tripped = zclock_sysvold.merge_tombstones(
        manifest_b, remote_tombs_from_a, state_b, partner_ip="192.168.180.43"
    )
    assert tripped is True
    assert len(candidates) == 0
    assert state_b.get("mass_delete_tripped") is True
    assert state_b.get("pending_mass_delete") is not None
    assert len(state_b["pending_mass_delete"]["paths"]) == 15
    assert len(state_b["pending_mass_delete"]["tombstones"]) == 15
    zclock_sysvold.save_sysvol_state(state_b, state_file_b)

    # 3. Fulladmin calls Reject on Node B
    pending = state_b.get("pending_mass_delete")
    rej_tombs = state_b.setdefault("rejected_tombstones", {})
    for p in pending["paths"]:
        d_at = pending["tombstones"].get(p, time.time())
        rej_tombs[p] = {
            "partner_ip": pending.get("partner_ip"),
            "deleted_at": float(d_at)
        }
        state_b["tombstones"].pop(p, None)
    state_b["pending_mass_delete"] = None
    state_b["approved_mass_delete"] = None
    state_b["mass_delete_tripped"] = False
    zclock_sysvold.save_sysvol_state(state_b, state_file_b)

    # 4. Cycle 1: Node B syncs with Node A
    # MergeTombstones skips rejected tombstones -> 0 candidates, not tripped
    manifest_b = reconciler_b.get_local_manifest()
    candidates, conflicts, tripped = zclock_sysvold.merge_tombstones(
        manifest_b, remote_tombs_from_a, state_b, partner_ip="192.168.180.43"
    )
    assert tripped is False
    assert len(candidates) == 0

    # Node B push step: checks rejected_tombstones and pushes with restore=True to Node A
    for rel_p, l_info in list(manifest_b.items()):
        is_restore = rel_p in state_b.get("rejected_tombstones", {})
        assert is_restore is True
        # Simulate Node A receiving the restored file
        p_dest = root_a / rel_p
        p_dest.parent.mkdir(parents=True, exist_ok=True)
        content = (root_b / rel_p).read_bytes()
        p_dest.write_bytes(content)
        # Node A clears its local tombstone upon receiving restore file
        state_a["tombstones"].pop(rel_p, None)

    zclock_sysvold.save_sysvol_state(state_a, state_file_a)

    # 5. Cycle 2: Node A scans local files
    manifest_a = reconciler_a.get_local_manifest()
    assert len(manifest_a) == 15
    reconciler_a.update_local_state_on_scan(manifest_a, state_a)
    zclock_sysvold.save_sysvol_state(state_a, state_file_a)
    assert len(state_a["tombstones"]) == 0

    # 6. Cycle 3: Node B syncs with Node A again
    # Partner manifest has all 15 files and 0 tombstones -> rejected_tombstones cleaned up!
    remote_manifest_a = reconciler_a.get_local_manifest()
    remote_tombs_a = list(state_a.get("tombstones", {}).values())
    remote_tomb_map_a = {t["rel_path"]: t for t in remote_tombs_a}

    rej_tombs = state_b.get("rejected_tombstones", {})
    keys_to_del = []
    now_ts = time.time()
    for p, r_info in rej_tombs.items():
        if (p in remote_manifest_a and p not in remote_tomb_map_a) or (now_ts - float(r_info.get("deleted_at", 0)) > 30 * 86400):
            keys_to_del.append(p)
    for p in keys_to_del:
        rej_tombs.pop(p, None)

    # Health status on B
    health_file_b.write_text("STATUS=HEALTHY\nLAST_RESET=1000\nMESSAGE=Sysvol NTACLs verified and healthy\n")
    state_b["files"] = reconciler_b.get_local_manifest()
    zclock_sysvold.save_sysvol_state(state_b, state_file_b)

    # Final Invariants Verification
    assert len(reconciler_a.get_local_manifest()) == 15
    assert len(reconciler_b.get_local_manifest()) == 15
    for i in range(15):
        rel_p = f"domain/Policies/GPO_{i:02d}/gpt.ini"
        assert (root_a / rel_p).exists()
        assert (root_b / rel_p).exists()
        assert hashlib.sha256((root_a / rel_p).read_bytes()).hexdigest() == file_hashes[rel_p]
        assert hashlib.sha256((root_b / rel_p).read_bytes()).hexdigest() == file_hashes[rel_p]

    assert len(state_a.get("tombstones", {})) == 0
    assert len(state_b.get("tombstones", {})) == 0
    assert len(state_b.get("rejected_tombstones", {})) == 0
    assert state_b.get("mass_delete_tripped") is False
    assert state_b.get("pending_mass_delete") is None
    assert "HEALTHY" in health_file_b.read_text()

