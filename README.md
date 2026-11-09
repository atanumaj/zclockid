# ZclockID Enterprise DC

**ZclockID** is an enterprise-grade, purpose-built, open-source Active Directory Domain Controller (AD DC) and Identity & Access Management (IAM) appliance. 

Engineered on Ubuntu Linux LTS, ZclockID replaces legacy monolithic suites by eliminating firewall, proxy, and mail bloat, focusing strictly on high-performance directory services, 802.1X network access, encrypted DNS-over-HTTPS (DoH), seamless Sysvol replication, and modern Web Single Sign-On.

---

## Quick Start: 1-Line Installation (Ubuntu 22.04 / 24.04 LTS)

On any fresh Ubuntu LTS machine, run:

```bash
curl -fsSL https://raw.githubusercontent.com/atanumaj/zclockid/master/installer/install.sh | sudo bash
```

After installation completes, navigate to:
* **Initial Setup Wizard:** `https://<server-ip>/setup.html`
* **Web Management Console:** `https://<server-ip>/`
* **User Self-Registration:** `https://<server-ip>/register.html`
* **REST API Documentation:** `http://<server-ip>:8000/docs`

For complete details and uninstallation instructions, see the [Installation Guide](docs/INSTALLATION.md).

---

## Complete Uninstallation & Purge

To completely wipe ZclockID, remove all packages, daemons, configuration files, and directory databases:

```bash
curl -fsSL https://raw.githubusercontent.com/atanumaj/zclockid/master/installer/uninstall.sh | sudo bash -s -- -y
```

---

## Key Features & Core Engines

* 🏛️ **Samba Active Directory Core:** Latest stable Samba AD DC with full support for Microsoft RSAT (`dsa.msc`, `gpmc.msc`, `dnsmgmt.msc`), Kerberos KDC, LDAP/LDAPS, and multi-DC Directory Replication Services (DRS).
* 🔒 **Encrypted DNS-over-HTTPS (DoH):** BIND 9.18+ DLZ (`BIND9_DLZ`) natively tied to Samba's `sam.ldb` with both traditional Port 53 UDP/TCP DNS and encrypted HTTP/2 DoH (`/dns-query`).
* 📶 **Transparent FreeRADIUS 802.1X Access:** Seamless network authentication for enterprise Wi-Fi and VPNs using Samba's `ntlm_auth` (MS-CHAPv2 / PEAP) and RFC 3580 Dynamic VLAN assignment based on Active Directory group membership.
* 🔄 **Bi-Directional Sysvol Sync with NTACL Self-Healing:** Dedicated `zclock-sysvold` engine that synchronizes Group Policy Objects while continuously repairing and preserving Windows Security Descriptors (`security.NTACL`).
* ⚡ **Headless REST API First:** 100% headless control via FastAPI with interactive OpenAPI (Swagger) documentation for automated provisioning, user lifecycle, and replication monitoring.
* 🌐 **Modern Identity & Web SSO:** Out-of-the-box SAML 2.0 and OpenID Connect (OIDC) federation with Kerberos SPNEGO for zero-touch desktop SSO on domain-joined PCs.
* 📊 **SNMP Telemetry & Metrics:** SNMP daemon with custom Active Directory OID extensions and Prometheus scraping metrics.

---

## Directory Structure

```
zclockid/
├── README.md                           # Master Project Overview
├── VERSION                             # Current release version
├── version-manifest.json               # Release channel & upgrade metadata
├── api/                                # Modular FastAPI backend
│   ├── core/                           # Configuration, Security & Licensing
│   ├── routers/                        # REST endpoints (Users, DNS, RADIUS, Domain, etc.)
│   ├── schemas/                        # Pydantic request/response models
│   └── services/                       # Samba, BIND9, FreeRADIUS, & Chrony engines
├── apt-repo/                           # Official signed APT Debian repository
├── config-templates/                   # Production service configuration templates
├── docs/                               # Comprehensive Technical & Operations Guides
│   ├── API_DOCUMENTATION.md            # REST API Specification & Examples
│   ├── INSTALLATION.md                 # 1-Line Installer & APT Repository Guide
│   └── USER_GUIDE.md                   # Administrator & Operations Manual
├── installer/                          # Automated install & uninstall shell scripts
├── package/                            # Debian packaging scripts & systemd definitions
├── scripts/                            # Sysvol daemon, telemetry & background workers
├── systemd/                            # Systemd service units
└── web/                                # Modular Glassmorphism Web Console UI
    ├── css/                            # Modern Tailwind & component styles
    └── js/                             # Modular JavaScript controllers
```

---

## Recommended System Specifications

| Component | Minimum Specification | Recommended Production |
| :--- | :--- | :--- |
| **Operating System** | Ubuntu 22.04 LTS or 24.04 LTS (x86_64) | Ubuntu 24.04 LTS (x86_64) |
| **CPU / vCPU** | 2 vCPU cores | 4+ vCPU cores |
| **RAM** | 4 GB | 8 GB - 16 GB |
| **Storage** | 30 GB SSD / NVMe | 60+ GB Enterprise SSD |
| **Networking** | 1 Gbps Static IPv4 | 10 Gbps Redundant LACP LAG |
| **Hypervisor** | VMware ESXi 6.7+, Proxmox, Hyper-V, KVM, Bare-metal | VMware ESXi / Proxmox VE / Bare-metal |

---

## Local Development & API Testing

### 1. Run the FastAPI Backend Locally
```bash
cd zclockid
python3 -m venv .venv && source .venv/bin/activate
pip install -r api/requirements.txt
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```
Access the interactive Swagger API documentation at `http://localhost:8000/docs`.

### 2. Test the Sysvol Self-Healing Daemon
```bash
cd zclockid/scripts
SYSVOL_PATH="/tmp/test_sysvol" python3 zclock-sysvold.py
```
