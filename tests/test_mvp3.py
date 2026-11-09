"""
End-to-End Verification Suite for ZclockID MVP 3 Features
Tests Hybrid RBAC, API Keys, SSL/TLS Certificates, and Remote Syslog / Live Streaming.
Target: https://192.168.1.41/
"""

import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://192.168.1.41/api/v1"

def test_mvp3():
    print("=" * 60)
    print("ZCLOCKID MVP 3 - LIVE END-TO-END VERIFICATION")
    print("Target: https://192.168.1.41/api/v1")
    print("=" * 60)

    session = requests.Session()
    session.verify = False

    # 1. Local Admin Authentication (Break-Glass)
    print("\n[TEST 1] Hybrid Login - Local Admin (Break-Glass)...")
    res = session.post(f"{BASE_URL}/auth/login", json={"username": "admin", "password": "ZclockID@Admin2026!"}, timeout=8)
    assert res.status_code == 200, f"Local login failed: {res.text}"
    local_data = res.json()
    print(f"  -> Local Admin Logged In: username={local_data.get('username')}, role={local_data.get('role')}, is_ad_user={local_data.get('is_ad_user')}")
    assert local_data.get("role") == "fulladmin", "Local admin should resolve to fulladmin"
    assert local_data.get("is_ad_user") is False, "Local admin should not be an AD user"

    # 2. Active Directory Domain Admin Authentication
    print("\n[TEST 2] Hybrid Login - Active Directory Domain Admin (Administrator)...")
    res = session.post(f"{BASE_URL}/auth/login", json={"username": "Administrator", "password": "ZclockID@Admin2026!"}, timeout=8)
    assert res.status_code == 200, f"AD login failed: {res.text}"
    ad_data = res.json()
    ad_token = ad_data.get("access_token") or ad_data.get("token")
    print(f"  -> AD Admin Logged In: username={ad_data.get('username')}, role={ad_data.get('role')}, is_ad_user={ad_data.get('is_ad_user')}")
    assert ad_data.get("role") == "fulladmin", "AD Administrator in Domain Admins should resolve to fulladmin"
    assert ad_data.get("is_ad_user") is True, "AD Administrator should be flagged as is_ad_user=True"

    headers = {"Authorization": f"Bearer {ad_token}"}

    # 3. RBAC /me Endpoint
    print("\n[TEST 3] RBAC Effective Permissions (/me)...")
    res = session.get(f"{BASE_URL}/rbac/me", headers=headers, timeout=5)
    assert res.status_code == 200, f"/me failed: {res.text}"
    me_data = res.json()
    print(f"  -> Effective Role: {me_data.get('role')}")
    print(f"  -> AD Groups: {me_data.get('groups')}")
    print(f"  -> Permissions Count: {len(me_data.get('permissions', []))}")
    assert "Domain Admins" in me_data.get("groups", []), "Administrator should be in Domain Admins"

    # 4. RBAC Roles & Mappings
    print("\n[TEST 4] RBAC Roles & Mapping Management...")
    res = session.get(f"{BASE_URL}/rbac/roles", headers=headers, timeout=5)
    assert res.status_code == 200
    roles = res.json().get("roles", [])
    print(f"  -> Available Roles: {[r['id'] for r in roles]}")
    assert len(roles) == 4, f"Expected 4 roles, got {len(roles)}"

    res = session.get(f"{BASE_URL}/rbac/mappings", headers=headers, timeout=5)
    assert res.status_code == 200
    mappings = res.json().get("mappings", [])
    print(f"  -> Total Configured Mappings: {len(mappings)}")
    dom_admin_map = next((m for m in mappings if m["principal_name"] == "Domain Admins"), None)
    assert dom_admin_map is not None, "Default Domain Admins mapping not found"
    print(f"  -> Verified Core Mapping: Domain Admins -> {dom_admin_map['role']}")

    # Create test mapping
    create_map_res = session.post(f"{BASE_URL}/rbac/mappings", headers=headers, json={
        "principal_type": "group",
        "principal_name": "Tier2-Helpdesk",
        "role": "operator",
        "description": "Automated Test Mapping"
    }, timeout=5)
    assert create_map_res.status_code == 200, f"Create mapping failed: {create_map_res.text}"
    test_map_id = create_map_res.json().get("id")
    print(f"  -> Created Test Mapping ID {test_map_id} (Tier2-Helpdesk -> operator)")

    # Delete test mapping
    del_res = session.delete(f"{BASE_URL}/rbac/mappings/{test_map_id}", headers=headers, timeout=5)
    assert del_res.status_code == 200, f"Delete mapping failed: {del_res.text}"
    print(f"  -> Deleted Test Mapping ID {test_map_id}")

    # 5. API Key Management
    print("\n[TEST 5] API Key Management (Token Generation & Revocation)...")
    key_res = session.post(f"{BASE_URL}/api-keys", headers=headers, json={
        "name": "Datadog Scraper Probe",
        "scopes": ["telemetry:read", "radius:read"],
        "cidr_whitelist": "192.168.1.0/24,10.0.0.0/8",
        "expires_days": 30
    }, timeout=5)
    assert key_res.status_code == 201, f"API key generation failed: {key_res.text}"
    key_data = key_res.json()
    new_token = key_data["full_api_key"]
    token_id = key_data["id"]
    print(f"  -> Created API Key ID {token_id}: prefix={key_data['key_prefix']}")
    assert new_token.startswith("zck_live_"), "API token must start with zck_live_"

    # List keys
    list_keys_res = session.get(f"{BASE_URL}/api-keys", headers=headers, timeout=5)
    assert list_keys_res.status_code == 200
    all_keys = list_keys_res.json()
    created_key = next((k for k in all_keys if k["id"] == token_id), None)
    assert created_key is not None, "Created API key not found in list"
    assert "full_api_key" not in created_key, "Raw API key must not be exposed in listing"
    print(f"  -> Listed {len(all_keys)} keys; Verified secret redaction.")

    # Revoke key
    rev_res = session.delete(f"{BASE_URL}/api-keys/{token_id}", headers=headers, timeout=5)
    assert rev_res.status_code == 200
    print(f"  -> Successfully Revoked API Key ID {token_id}")

    # 6. SSL/TLS Certificate Inspection & CSR Generation
    print("\n[TEST 6] SSL/TLS Certificate Inspection & CSR...")
    cert_res = session.get(f"{BASE_URL}/certificates/active", headers=headers, timeout=5)
    assert cert_res.status_code == 200, f"Cert inspection failed: {cert_res.text}"
    cert_data = cert_res.json()
    print(f"  -> Subject: {cert_data.get('subject')}")
    print(f"  -> Issuer: {cert_data.get('issuer')}")
    print(f"  -> Status: {cert_data.get('status')}")
    print(f"  -> Days Remaining: {cert_data.get('days_remaining')}")
    print(f"  -> SANs: {cert_data.get('san_list')}")
    assert cert_data.get("days_remaining", 0) > 0, "Active certificate must not be expired"

    # Test CSR Generation
    csr_res = session.post(f"{BASE_URL}/certificates/csr", headers=headers, json={
        "common_name": "zclockid-dc.corp.example.com",
        "organization": "ZclockID Enterprise",
        "city": "Austin",
        "state": "Texas",
        "country": "US",
        "san_list": ["10.0.0.10", "zclockid-dc.corp.example.com"]
    }, timeout=5)
    assert csr_res.status_code == 200, f"CSR generation failed: {csr_res.text}"
    csr_pem = csr_res.json().get("csr_pem", "")
    assert "-----BEGIN CERTIFICATE REQUEST-----" in csr_pem, "Invalid CSR PEM format"
    print(f"  -> Generated CSR PEM ({len(csr_pem)} chars)")

    # Test Active Cert Download
    dl_res = session.get(f"{BASE_URL}/certificates/download/active", timeout=5)
    assert dl_res.status_code == 200
    assert "-----BEGIN CERTIFICATE-----" in dl_res.text, "Active cert download failed"
    print(f"  -> Downloaded Active Certificate (.crt) successfully ({len(dl_res.text)} bytes)")

    # 7. Remote Syslog & Categorized Live Log Streaming
    print("\n[TEST 7] Syslog & Categorized Live Logs...")
    syslog_res = session.get(f"{BASE_URL}/syslog/settings", headers=headers, timeout=5)
    assert syslog_res.status_code == 200
    sys_settings = syslog_res.json()
    print(f"  -> Current Syslog Settings: enabled={sys_settings.get('enabled')}, port={sys_settings.get('remote_port')}")

    # Update syslog settings
    put_sys_res = session.put(f"{BASE_URL}/syslog/settings", headers=headers, json={
        "enabled": False,
        "remote_host": "192.168.1.50",
        "remote_port": 514,
        "protocol": "UDP",
        "facility": "local0",
        "log_format": "RFC5424",
        "send_samba_logs": True,
        "send_radius_logs": True,
        "send_auth_logs": True,
        "send_system_logs": True
    }, timeout=5)
    assert put_sys_res.status_code == 200
    print("  -> Updated Syslog Settings to target 192.168.1.50:514 (UDP)")

    # Fetch categorized logs
    for cat in ["samba", "radius", "auth", "audit", "system"]:
        log_res = session.get(f"{BASE_URL}/syslog/logs?category={cat}&lines=10", headers=headers, timeout=5)
        assert log_res.status_code == 200, f"Fetch logs failed for {cat}: {log_res.text}"
        logs = log_res.json().get("logs", [])
        print(f"  -> Streamed {len(logs)} log entries from category [{cat}]")

    print("\n" + "=" * 60)
    print("ALL MVP 3 TEST SUITES PASSED CLEANLY ON TARGET APPLIANCE!")
    print("=" * 60)

if __name__ == "__main__":
    test_mvp3()
