import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
s = requests.Session()
s.verify = False

# 1. Login
r = s.post("https://192.168.1.41/api/v1/auth/login", json={"username": "admin", "password": "P@ssw0rd@inet"})
assert r.status_code == 200, f"Login failed: {r.text}"
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

print("=== 1. SSPR Flow on VM (192.168.1.41) ===")
# Temporarily enable SMTP in SSPR settings so channel is active
orig_settings = s.get("https://192.168.1.41/api/v1/self-service/password/settings", headers=headers).json().get("settings", {})
s.post("https://192.168.1.41/api/v1/self-service/password/settings", json={
    **orig_settings,
    "email_smtp_enabled": True,
    "smtp_host": "127.0.0.1"
}, headers=headers)

try:
    # request-otp with active channel
    r_otp = s.post("https://192.168.1.41/api/v1/self-service/password/request-otp", json={"username": "admin", "channel": "email"})
    print("request-otp status:", r_otp.status_code)
    otp_data = r_otp.json()
    reset_token = otp_data.get("reset_token", "")
    has_reset_token = "reset_token" in otp_data
    has_reset_id = "reset_id" in otp_data
    print(f"has reset_token: {has_reset_token} (length: {len(reset_token)})")
    print(f"has reset_id: {has_reset_id}")

    # verify-and-reset with legacy reset_id -> rejected
    r_legacy = s.post("https://192.168.1.41/api/v1/self-service/password/verify-and-reset", json={
        "reset_id": 9999,
        "otp_code": "123456",
        "new_password": "NewSecretPassword123!"
    })
    print("verify-and-reset with reset_id status:", r_legacy.status_code, r_legacy.json())

    # verify-and-reset with valid reset_token but wrong code -> attempts remaining
    r_verify = s.post("https://192.168.1.41/api/v1/self-service/password/verify-and-reset", json={
        "reset_token": reset_token,
        "otp_code": "000000",
        "new_password": "NewSecretPassword123!"
    })
    print("verify-and-reset with reset_token wrong code status:", r_verify.status_code, r_verify.json())
finally:
    # Revert settings
    s.post("https://192.168.1.41/api/v1/self-service/password/settings", json=orig_settings, headers=headers)

print("\n=== 2. SYSVOL Partner Fingerprint Mismatch on VM (192.168.1.41) ===")
# Confirm without cert_fingerprint
r_no_fp = s.post("https://192.168.1.41/api/v1/sysvol/partners", json={
    "name": "DC-NoFp",
    "ip_address": "127.0.0.1",
    "shared_secret": "test_secret_1234",
    "confirm": True
}, headers=headers)
print("SYSVOL confirm without fingerprint status:", r_no_fp.status_code, r_no_fp.json())

# Fingerprint mismatch against localhost (probed vs submitted)
r_mismatch = s.post("https://192.168.1.41/api/v1/sysvol/partners", json={
    "name": "DC-Mismatch",
    "ip_address": "127.0.0.1",
    "shared_secret": "test_secret_1234",
    "cert_fingerprint": "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
    "confirm": True
}, headers=headers)
print("SYSVOL fingerprint mismatch status:", r_mismatch.status_code, r_mismatch.json())
