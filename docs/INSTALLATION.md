# ZclockID Appliance Installation & Operations Guide (Ubuntu LTS)

ZclockID is an open-source, purpose-built Active Directory Domain Controller and IAM appliance engineered for **Ubuntu 22.04 LTS & 24.04 LTS**.

---

## 1. Quick Start: Automated 1-Line Installation

On any fresh Ubuntu LTS machine, run the following one-line command as root:

```bash
curl -fsSL https://raw.githubusercontent.com/atanumaj/zclockid/master/installer/install.sh | sudo bash
```

### What this script does automatically:
1. Adds the official **ZclockID Ubuntu APT repository** (`/etc/apt/sources.list.d/zclockid.list`).
2. Configures non-interactive pre-seeding for Kerberos (`krb5-config`).
3. Installs `zclockid` (v1.0.0) alongside all upstream dependencies:
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
   https://<server-ip>/setup.html
   ```
   *(Accept the self-signed SSL certificate).*
2. Configure your AD parameters:
   * **Domain Realm (FQDN):** e.g., `corp.example.com` or `inet.net`
   * **NetBIOS Name:** e.g., `CORP` or `INET`
   * **Administrator Password:** Set your master domain password.
3. Click **Provision Domain Controller**. The wizard provisions the SAM LDB directory, configures BIND9 DNS forwarders, and starts all AD services.
4. Access the main management console at `https://<server-ip>/` and sign in with `administrator` and your password.

---

## 3. Manual Installation (Alternative)

If you prefer to manually configure the APT repository or install the `.deb` package directly:

### Option A: Via APT Repository
```bash
# 1. Add repository source
sudo bash -c 'cat << EOF > /etc/apt/sources.list.d/zclockid.list
deb [trusted=yes] https://raw.githubusercontent.com/atanumaj/zclockid/master/apt-repo stable main
EOF'

# 2. Update and install
sudo apt-get update
sudo apt-get install -y zclockid
```

### Option B: Direct DEB Package Installation
```bash
# Download package from GitHub
wget https://raw.githubusercontent.com/atanumaj/zclockid/master/apt-repo/pool/main/zclockid_1.0.0_all.deb

# Install package and resolve dependencies
sudo apt-get update
sudo apt-get install -y ./zclockid_1.0.0_all.deb
```

---

## 4. Updates & Upgrades

### Checking Updates via Web Console
Navigate to **Security & Management > Software Updates**. Click **Check Updates** to query new releases. When a new version is available, click **Install Update Now** to upgrade with zero downtime.

### Upgrading via APT CLI
```bash
sudo apt-get update
sudo apt-get --only-upgrade install zclockid
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
sudo rm -f /etc/apt/sources.list.d/zclockid.list /etc/nginx/sites-enabled/zclockid.conf /etc/nginx/sites-available/zclockid.conf
sudo systemctl daemon-reload
```
