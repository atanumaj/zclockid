# ZclockID Appliance Installation & Operations Guide (Ubuntu LTS)

ZclockID is an open-source, purpose-built Active Directory Domain Controller and IAM appliance engineered for **Ubuntu 22.04 LTS & 24.04 LTS**.

---

## 1. Quick Start: 1-Line Installation via GitHub

On your target Ubuntu machine, run as root:

```bash
curl -fsSL https://raw.githubusercontent.com/atanumaj/zclockid/master/installer/install.sh | sudo bash
```

### What this script does automatically:
1. Adds `/etc/apt/sources.list.d/zclockid.sources` (modern DEB822 format) and `/etc/apt/sources.list.d/zclockid.list` pointing to the ZclockID repository.
2. Configures non-interactive pre-seeding for Kerberos (`krb5-config`).
3. Installs `zclockid` alongside all upstream dependencies:
   * Samba Active Directory Domain Controller (`samba-ad-dc`)
   * BIND9 DLZ with DNS-over-HTTPS (`bind9`)
   * FreeRADIUS 3 with MS-CHAP & EAP 802.1X (`freeradius`)
   * Chrony Authenticated NTP Server (`chrony`)
   * Nginx Multiplexing TLS Ingress Proxy (`nginx`)
   * SNMP Telemetry Daemon (`snmpd`)
4. Decouples `systemd-resolved` from Port 53 while preserving host Netplan configuration.
5. Deploys systemd services (`zclock-api`, `zclock-sysvold`, `zclock-azuresync`) and generates initial TLS certificates.
6. Launches the Web Console at `https://<server-ip>/`.

---

## 2. First-Time Setup Wizard

1. Open your browser and navigate to:
   ```text
   https://<your-server-ip>/
   ```
   *(Accept the self-signed SSL certificate. The appliance automatically detects that no admin account exists and redirects directly to `/setup.html`).*
2. Configure your AD parameters:
   * **Admin Account:** Define your web administrator username, password, and email.
   * **Appliance Hostname:** Set a clean Linux hostname and DC NetBIOS computer name (e.g., `dc01`, `zclock-dc`).
   * **Domain Role:** Choose New Forest (Primary DC) or Join Existing Forest (Secondary DC).
   * **Domain Realm (FQDN):** e.g., `corp.example.com`
   * **NetBIOS Name:** e.g., `CORP`
   * **Master AD Administrator Password:** Set your master Active Directory administrator password.
3. Click **Provision Domain Controller**. The wizard provisions the SAM LDB directory, configures BIND9 DNS forwarders, and starts all AD services.
4. Access the main management console at `https://<your-server-ip>/` and sign in.

---

## 3. Manual Installation (Alternative)

If you prefer to manually configure the APT repository or install the `.deb` package directly:

### Option A: Via APT Repository
```bash
# 1. Install official archive signing key
sudo mkdir -p /usr/share/keyrings
sudo curl -fsSL https://raw.githubusercontent.com/atanumaj/zclockid/master/package/keyrings/zclockid-archive-keyring.gpg -o /usr/share/keyrings/zclockid-archive-keyring.gpg
sudo chmod 644 /usr/share/keyrings/zclockid-archive-keyring.gpg

# Official Release Signing Key Fingerprint:
# F85A 5376 2E2B ADA8 C5FF  6AF4 408D 10F3 F786 00EE

# 2. Add repository source (DEB822 format for Ubuntu 24.04/22.04)
sudo bash -c 'cat << EOF > /etc/apt/sources.list.d/zclockid.sources
Types: deb
URIs: https://raw.githubusercontent.com/atanumaj/zclockid/master/apt-repo
Suites: stable
Components: main
Signed-By: /usr/share/keyrings/zclockid-archive-keyring.gpg
EOF'

# Or standard one-line source:
sudo bash -c 'cat << EOF > /etc/apt/sources.list.d/zclockid.list
deb [signed-by=/usr/share/keyrings/zclockid-archive-keyring.gpg] https://raw.githubusercontent.com/atanumaj/zclockid/master/apt-repo stable main
EOF'

# 3. Update and install
sudo apt-get update
sudo apt-get install -y zclockid
```

### Option B: Direct DEB Package Installation (Cryptographically Verified)
```bash
# 1. Ensure private update staging directory exists with strict permissions (mode 0700)
sudo mkdir -p /var/lib/zclockid/updates
sudo chown root:root /var/lib/zclockid/updates
sudo chmod 700 /var/lib/zclockid/updates

# 2. Download package and detached signature from GitHub repository
sudo curl -fsSL "https://raw.githubusercontent.com/atanumaj/zclockid/master/apt-repo/pool/main/zclockid_1.4.1_all.deb" -o /var/lib/zclockid/updates/zclockid_update.deb
sudo curl -fsSL "https://raw.githubusercontent.com/atanumaj/zclockid/master/apt-repo/pool/main/zclockid_1.4.1_all.deb.sig" -o /var/lib/zclockid/updates/zclockid_update.deb.sig

# 3. Cryptographically verify package signature using the official keyring
gpgv --keyring /usr/share/keyrings/zclockid-archive-keyring.gpg /var/lib/zclockid/updates/zclockid_update.deb.sig /var/lib/zclockid/updates/zclockid_update.deb

# 4. Install package and resolve dependencies
sudo apt-get update
sudo apt-get install -y /var/lib/zclockid/updates/zclockid_update.deb
```

---

## 4. Updates & Upgrades

### Checking Updates via Web Console
Navigate to **Security & Management > Software Updates**. Click **Check Updates** to query new releases against the upstream channel. When a new version is available, click **Install Update Now** to upgrade with zero downtime. Updates are staged in `/var/lib/zclockid/updates/` (mode 0700) and cryptographically verified prior to execution.

### CLI Upgrades via Appliance Updater Script (Recommended)
Download the latest Debian package and detached signature into the secure staging directory `/var/lib/zclockid/updates/` and invoke the appliance's built-in background updater script. The updater script validates the cryptographic signature using the trusted keyring (failing closed if signature or keyring is missing), creates a pre-upgrade safety snapshot under `/var/backups/zclockid/`, resolves dependencies, and safely restarts the management daemon without interrupting Active Directory Samba services:

```bash
# 1. Ensure updates directory exists with mode 0700
sudo mkdir -p /var/lib/zclockid/updates
sudo chmod 700 /var/lib/zclockid/updates

# 2. Fetch the latest release package and signature
sudo curl -fsSL "https://raw.githubusercontent.com/atanumaj/zclockid/master/apt-repo/pool/main/zclockid_1.4.1_all.deb" -o /var/lib/zclockid/updates/zclockid_update.deb
sudo curl -fsSL "https://raw.githubusercontent.com/atanumaj/zclockid/master/apt-repo/pool/main/zclockid_1.4.1_all.deb.sig" -o /var/lib/zclockid/updates/zclockid_update.deb.sig

# 3. Run the automated updater script (fails closed if signature is missing or tampered)
sudo /opt/zclockid/scripts/zclock-updater.sh /var/lib/zclockid/updates/zclockid_update.deb
```

Alternatively, apply the package directly via `dpkg`:
```bash
sudo dpkg -i /var/lib/zclockid/updates/zclockid_update.deb
```

---

## 5. Complete Uninstallation & Purge

To completely wipe ZclockID, remove all services, configuration files, and databases from the system:

### 1-Line Automated Uninstaller:
```bash
curl -fsSL https://raw.githubusercontent.com/atanumaj/zclockid/master/installer/uninstall.sh | sudo bash -s -- -y
```

### Manual Purge:
```bash
# 1. Stop daemons
sudo systemctl stop zclock-api zclock-sysvold zclock-azuresync

# 2. Purge package
sudo apt-get purge -y zclockid
sudo apt-get autoremove -y

# 3. Clean directories & configs
sudo rm -rf /opt/zclockid /zclockid /etc/zclockid /var/lib/zclockid /var/log/zclockid /etc/systemd/system/zclock-*.service
sudo rm -f /etc/apt/sources.list.d/zclockid.* /etc/nginx/sites-enabled/zclockid.conf /etc/nginx/sites-available/zclockid.conf
sudo systemctl daemon-reload
```
