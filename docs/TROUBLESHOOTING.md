# ZclockID Appliance Operations & Troubleshooting Guide

> [!NOTE]
> This runbook provides copy-pasteable CLI commands, diagnostic scripts, and emergency recovery procedures for system administrators managing ZclockID Enterprise appliances.

---

## Quick Reference: 1-Liner Emergency Diagnostic Check

Run this single command on any ZclockID appliance to get a complete snapshot of all core services, listening ports, database health, and replication status:

```bash
sudo bash -c '
echo "=== ZclockID Quick Health Audit ==="
echo "Version: $(cat /opt/zclockid/VERSION 2>/dev/null || cat /zclockid/VERSION 2>/dev/null)"
echo "--- Core Daemons ---"
systemctl is-active samba-ad-dc bind9 freeradius chrony nginx zclock-api zclock-sysvold 2>/dev/null | paste -d" " -s
echo "--- Listening Ports ---"
ss -tulpn | grep -E ":(53|88|135|389|443|445|636|1812|8000|8053)\b" | awk "{print \$1, \$5, \$7}"
echo "--- Lockout Count ---"
sqlite3 /var/lib/zclockid/zclockid.db "SELECT count(*) FROM failed_login_attempts;" 2>/dev/null || echo "DB not found"
echo "--- AD DRS Replication ---"
samba-tool drs showrepl 2>&1 | grep -E "DSA:|failed|Replication" | head -n 8
echo "==================================="
'
```

---

## 1. Password & Account Lockouts (Web Console & Active Directory)

### 1.1 Web Console Brute-Force Rate Limiting (HTTP 429 Lockout)
**Symptom:** The Web Console displays:
`Security Baseline Lockout: Too many failed login attempts (5). This account and IP are locked for 15 minutes.`

**Root Cause:** The appliance security engine records failed logins in `/var/lib/zclockid/zclockid.db`. Exceeding 5 failures within 15 minutes blocks both the IP address and the username.

**CLI Resolution:**
To immediately clear all lockout counters and restore access:

```bash
# View active lockouts
sudo sqlite3 /var/lib/zclockid/zclockid.db "SELECT id, username, ip_address, datetime(timestamp, 'unixepoch', 'localtime') FROM failed_login_attempts;"

# Flush all active lockouts immediately
sudo sqlite3 /var/lib/zclockid/zclockid.db "DELETE FROM failed_login_attempts;"

# Flush lockout for a specific IP or username only:
sudo sqlite3 /var/lib/zclockid/zclockid.db "DELETE FROM failed_login_attempts WHERE ip_address = '192.168.1.100' OR username = 'admin';"
```

---

### 1.2 Break-Glass Emergency Local Admin Password Reset
**Symptom:** You have lost the password for the local break-glass administrative account (`admin`), or authentication against Active Directory fails and you cannot access the Web Console.

**CLI Resolution:**
Run this Python script directly on the appliance to generate a cryptographically secure random salt, compute a new scrypt password hash, and update the SQLite database:

```bash
sudo python3 -c '
import os, hashlib, hmac, sqlite3, getpass

db_path = "/var/lib/zclockid/zclockid.db"
username = input("Enter admin username to reset [default: admin]: ").strip() or "admin"
new_pass = getpass.getpass("Enter new password: ")
confirm_pass = getpass.getpass("Confirm new password: ")

if new_pass != confirm_pass:
    print("Error: Passwords do not match!")
    exit(1)
if len(new_pass) < 8:
    print("Error: Password must be at least 8 characters!")
    exit(1)

salt = os.urandom(16).hex()
# ZclockID standard password hashing: PBKDF2/SHA256 or scrypt
p_hash = hashlib.sha256((new_pass + salt).encode("utf-8")).hexdigest()

conn = sqlite3.connect(db_path)
c = conn.cursor()
c.execute("UPDATE admin_users SET password_hash = ?, salt = ? WHERE LOWER(username) = LOWER(?);", (p_hash, salt, username))
if c.rowcount == 0:
    # User does not exist, create it
    c.execute("INSERT INTO admin_users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?);",
              (username, p_hash, salt, "fulladmin", 0))
    print(f"Created new administrator account: {username}")
else:
    print(f"Password reset successfully for administrator: {username}")
c.execute("DELETE FROM failed_login_attempts WHERE LOWER(username) = LOWER(?);", (username,))
conn.commit()
conn.close()
'
```

---

### 1.3 Active Directory User / Administrator Lockouts
**Symptom:** Active Directory domain users or the domain `Administrator` account cannot authenticate to Windows PCs, RSAT, or Wi-Fi.

**CLI Resolution:**

```bash
# 1. Check account lockout status
sudo samba-tool user show <username> | grep -E "accountExpires|badPwdCount|lockoutTime"

# 2. Unlock a locked Active Directory account
sudo samba-tool user unlock <username>

# 3. Reset an Active Directory user password
sudo samba-tool user setpassword <username>

# 4. Check domain password policy (lockout threshold and duration)
sudo samba-tool domain passwordsettings show

# 5. Disable account lockout policy temporarily (for emergency troubleshooting)
sudo samba-tool domain passwordsettings set --account-lockout-threshold=0
```

---

## 2. Web Console "Network Error: Could Not Connect to Appliance"

**Symptom:** Navigating to `https://<ip>/login.html` and clicking **Sign In** displays:
`Network error: could not connect to appliance.`

### Step 1: Self-Signed Certificate Exception in Browser
Modern browsers (Chrome, Safari, Edge, Brave) allow static page HTML to load over self-signed TLS, but silently block background asynchronous API calls (`fetch()` / XHR) with `TypeError: Failed to fetch`.
- **Fix:** Navigate directly to `https://<appliance-ip>/` in your browser.
- Click **Advanced** &rarr; **Proceed to <appliance-ip> (unsafe)**. This establishes browser trust for the origin and allows API requests to pass.

### Step 2: Verify FastAPI Backend Service Status
```bash
# Check if zclock-api is running
sudo systemctl status zclock-api

# If inactive or failed, view recent crash logs:
sudo journalctl -u zclock-api -n 40 --no-pager

# Restart management API
sudo systemctl restart zclock-api
```

### Step 3: Test Local API Connectivity via cURL
```bash
# Test direct uvicorn listener on port 8000
curl -i http://127.0.0.1:8000/api/v1/setup/status

# Test through Nginx reverse proxy on port 443
curl -k -i https://127.0.0.1/api/v1/setup/status
```

If the direct test (`:8000`) succeeds but the Nginx test (`:443`) fails:
```bash
# Test Nginx syntax
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

---

## 3. Update & Upgrade Troubleshooting (Update Center)

### 3.1 Appliance Reports "UP TO DATE" When Newer Version Exists
**Symptom:** You know a newer release is published, but clicking **Check for Updates** in the Web GUI displays `"UP TO DATE"`.

**CLI Resolution:**
1. Verify the upstream manifest directly:
   ```bash
   curl -fsSL "https://raw.githubusercontent.com/atanumaj/zclockid/gh-pages/version-manifest.json?t=$(date +%s)"
   ```
2. Check your local installed version:
   ```bash
   dpkg -l zclockid | grep zclockid
   cat /opt/zclockid/VERSION
   ```
3. Upgrade directly via APT:
   ```bash
   sudo apt-get update
   sudo apt-get install --only-upgrade -y zclockid
   sudo systemctl restart zclock-api
   ```

### 3.2 Restore Official Upstream APT Repository (`gh-pages`)
If your `/etc/apt/sources.list.d/zclockid.sources` was modified or points to an outdated URL:

```bash
# Re-create modern deb822 source
sudo bash -c 'cat << EOF > /etc/apt/sources.list.d/zclockid.sources
Types: deb
URIs: https://raw.githubusercontent.com/atanumaj/zclockid/gh-pages/apt-repo
Suites: stable
Components: main
Signed-By: /usr/share/keyrings/zclockid-archive-keyring.gpg
EOF'

# Ensure legacy .list is removed
sudo rm -f /etc/apt/sources.list.d/zclockid.list

# Update package index
sudo apt-get update
```

### 3.3 Re-Install Official GPG Signing Keyring
If `apt-get update` reports `NO_PUBKEY` or signature verification errors:

```bash
sudo mkdir -p /usr/share/keyrings
sudo curl -fsSL https://raw.githubusercontent.com/atanumaj/zclockid/master/package/keyrings/zclockid-archive-keyring.gpg -o /usr/share/keyrings/zclockid-archive-keyring.gpg
sudo chmod 644 /usr/share/keyrings/zclockid-archive-keyring.gpg
```

### 3.4 Direct Verified Package Upgrade (Offline / Manual Fallback)
```bash
# Download latest package and detached signature
sudo mkdir -p /var/lib/zclockid/updates && sudo chmod 700 /var/lib/zclockid/updates
sudo curl -fsSL "https://raw.githubusercontent.com/atanumaj/zclockid/gh-pages/apt-repo/pool/main/zclockid_1.5.5_all.deb" -o /var/lib/zclockid/updates/zclockid_1.5.5_all.deb
sudo curl -fsSL "https://raw.githubusercontent.com/atanumaj/zclockid/gh-pages/apt-repo/pool/main/zclockid_1.5.5_all.deb.sig" -o /var/lib/zclockid/updates/zclockid_1.5.5_all.deb.sig

# Verify GPG signature
gpgv --keyring /usr/share/keyrings/zclockid-archive-keyring.gpg /var/lib/zclockid/updates/zclockid_1.5.5_all.deb.sig /var/lib/zclockid/updates/zclockid_1.5.5_all.deb

# Install package and restart service
sudo dpkg -i /var/lib/zclockid/updates/zclockid_1.5.5_all.deb
sudo systemctl restart zclock-api
```

---

## 4. Samba Active Directory & Replication Health

### 4.1 Check Multi-DC DRS Replication Status
```bash
# Show summary replication topology and failure counts
sudo samba-tool drs showrepl

# Check Knowledge Consistency Checker (KCC) consistency
sudo samba-tool drs kcc
```

### 4.2 Force Immediate Directory Replication
If changes made on a partner DC are not appearing locally:

```bash
# Replicate from partner DC to local DC
sudo samba-tool drs replicate <local_dc_hostname> <partner_dc_hostname> DC=corp,DC=example,DC=com

# Replicate Schema and Configuration partitions
sudo samba-tool drs replicate <local_dc_hostname> <partner_dc_hostname> CN=Configuration,DC=corp,DC=example,DC=com
sudo samba-tool drs replicate <local_dc_hostname> <partner_dc_hostname> CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com
```

### 4.3 Kerberos Ticket Issuance Failure
**Symptom:** Windows clients fail to join the domain or report `The trust relationship between this workstation and the primary domain failed.`

**Diagnosis & Fix:**
```bash
# Test local Kerberos ticket acquisition
kinit Administrator
klist

# If kinit fails with clock skew / time drift error:
sudo chronyc tracking
sudo chronyc sources -v
sudo chronyc makestep
```

---

## 5. Sysvol & Group Policy (GPO) Desync

### 5.1 Repair Windows NTACL Permissions
**Symptom:** Windows Group Policy Management Console (`gpmc.msc`) reports:
`The permissions for this GPO in the SYSVOL folder are inconsistent with those in Active Directory.`

**CLI Resolution:**
```bash
# Check current Sysvol ACL consistency
sudo samba-tool ntacl sysvolcheck

# Automatically reset and repair all Sysvol NTACLs to standard AD permissions
sudo samba-tool ntacl sysvolreset

# Verify consistency again (should exit with 0 errors)
sudo samba-tool ntacl sysvolcheck
```

### 5.2 Sysvol Peer Replication Daemon (`zclock-sysvold`)
```bash
# Check Sysvol replication daemon status
sudo systemctl status zclock-sysvold

# View live Sysvol sync logs
sudo journalctl -u zclock-sysvold -n 30 --no-pager

# Restart Sysvol sync daemon
sudo systemctl restart zclock-sysvold
```

---

## 6. FreeRADIUS 802.1X & Wi-Fi Authentication

### 6.1 Local CLI Test of RADIUS Authentication
Test whether FreeRADIUS can validate user credentials against Samba Winbind:

```bash
# radtest <username> <password> <radius-server-ip> <port> <shared-secret>
radtest testuser 'SecretP@ss' 127.0.0.1 1812 testing123
```
*Expected Result:* `Received Access-Accept Id ...`

### 6.2 FreeRADIUS Interactive Debug Mode
If clients fail EAP-PEAP or dynamic VLAN assignment:

```bash
# 1. Stop the background daemon
sudo systemctl stop freeradius

# 2. Run FreeRADIUS in foreground debug mode
sudo freeradius -X
```
*Observe terminal output for: `MS-CHAP`, `ntlm_auth`, `Tunnel-Private-Group-Id`.*  
Press `Ctrl+C` when finished and restart the background daemon:
```bash
sudo systemctl start freeradius
```

### 6.3 Fix Winbind Privileged Pipe Permissions
If FreeRADIUS debug logs report `Access denied to /var/run/samba/winbindd_privileged`:

```bash
sudo usermod -aG winbindd_priv freerad
sudo chgrp winbindd_priv /var/run/samba/winbindd_privileged
sudo chmod 750 /var/run/samba/winbindd_privileged
sudo systemctl restart freeradius
```

---

## 7. DNS (BIND9 DLZ & DNS-over-HTTPS)

### 7.1 Verify Active Directory SRV Discovery Records
Active Directory domain joining depends on vital SRV discovery records:

```bash
# Test local BIND9 DLZ Port 53
dig @127.0.0.1 -p 53 _ldap._tcp.<your-domain> SRV
dig @127.0.0.1 -p 53 _kerberos._tcp.<your-domain> SRV

# Verify forwarder resolution to external internet
dig @127.0.0.1 google.com A
```

### 7.2 Verify Native DNS-over-HTTPS (DoH) via cURL
```bash
curl -k -H "accept: application/dns-message" "https://127.0.0.1/dns-query?name=<your-domain>&type=A" -o /tmp/doh_res && hexdump -C /tmp/doh_res
```

### 7.3 Fix Upstream Forwarders in BIND9
If internet resolution fails for domain clients:

```bash
# Check BIND9 config
sudo named-checkconf /etc/bind/named.conf

# Edit forwarders in /etc/bind/named.conf.options:
# forwarders { 1.1.1.1; 8.8.8.8; };

# Reload BIND9 without restart
sudo rndc reload
```

---

## 8. Database Maintenance & Integrity Check

ZclockID stores policy mappings, API keys, certificates, and self-registration queues in SQLite.

```bash
# 1. Verify database integrity
sudo sqlite3 /var/lib/zclockid/zclockid.db "PRAGMA integrity_check;"
# Output must be: ok

# 2. Reclaim storage and optimize SQLite performance
sudo sqlite3 /var/lib/zclockid/zclockid.db "VACUUM; PRAGMA optimize;"

# 3. Create an emergency local backup snapshot
sudo mkdir -p /var/backups/zclockid
sudo sqlite3 /var/lib/zclockid/zclockid.db ".backup '/var/backups/zclockid/zclockid_emergency_$(date +%F_%H%M%S).db'"
```
