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

* 🏛️ **Samba Active Directory Core:** Latest stable, fully patched Samba AD DC with full support for Microsoft RSAT (`dsa.msc`, `gpmc.msc`, `dnsmgmt.msc`), Kerberos KDC, LDAP/LDAPS, and multi-DC Directory Replication Services (DRS).
* 🔒 **Encrypted DNS-over-HTTPS (DoH):** BIND 9.18+ DLZ (`BIND9_DLZ`) natively tied to Samba's `sam.ldb` with both traditional Port 53 UDP/TCP DNS and encrypted HTTP/2 DoH (`/dns-query`).
* 📶 **Transparent FreeRADIUS 802.1X Access:** Seamless network authentication for enterprise Wi-Fi and VPNs using Samba's `ntlm_auth` (MS-CHAPv2 / PEAP) and RFC 3580 Dynamic VLAN assignment based on Active Directory group membership.
* 🔄 **Bi-Directional Sysvol Sync with NTACL Self-Healing:** Dedicated `zclock-sysvold` engine that synchronizes Group Policy Objects while continuously repairing and preserving Windows Security Descriptors (`security.NTACL`).
* ⚡ **Headless REST API First:** 100% headless control via FastAPI with interactive OpenAPI (Swagger) documentation for automated provisioning, user lifecycle, and replication monitoring.
* 🌐 **Modern Identity & Web SSO (Keycloak):** Out-of-the-box SAML 2.0 and OpenID Connect (OIDC) federation with Kerberos SPNEGO for zero-touch desktop SSO on domain-joined PCs.
* 📊 **SNMP Telemetry & Metrics:** SNMP daemon with custom Active Directory OID extensions and Prometheus scraping metrics.

---

## Directory Structure

```
Inet-ZclockID/
├── README.md                           # Master Project Overview
├── docs/
│   ├── USER_GUIDE.md                   # Administrator & User Manual (Sizing, Install, Bandwidth, DNS)
│   ├── FEASIBILITY_ANALYSIS.md         # Comprehensive Feasibility & Zentyal Comparison
│   ├── ARCHITECTURE.md                 # System Architecture, Port Matrix & Data Flows
│   ├── ENGINES_SPECIFICATION.md        # Technical Specs for Samba, BIND9, FreeRADIUS, Sysvol, SSO
│   ├── API_SPECIFICATION.md            # Headless REST API Specification & Endpoints
│   └── ROADMAP_AND_COMMERCIALIZATION.md # GTM Strategy, OVA Packaging, Sizing & Sched
├── config-templates/
│   ├── samba/                          # Baseline smb.conf & provisioning templates
│   ├── bind9/                          # named.conf.options & DLZ driver templates
│   ├── freeradius/                     # mschap, inner-tunnel, & clients.conf templates
│   ├── snmp/                           # snmpd.conf with custom AD OIDs
│   └── keycloak/                       # LDAP user federation schema & realm blueprints
├── scripts/
│   ├── zclock-sysvold.py               # Bi-directional Sysvol sync & NTACL self-healing daemon
│   └── zclock-telemetry.sh             # SNMP pass-through script for live AD telemetry
└── api-prototype/
    ├── main.py                         # FastAPI Headless REST API implementation
    └── requirements.txt                # Python API dependencies
```

---

## Quick Start / Local Prototype Testing

### 1. Test the Headless REST API Prototype
```bash
cd Inet-ZclockID/api-prototype
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
Access the interactive Swagger API documentation at `http://localhost:8000/docs`.

### 2. Test the Sysvol Self-Healing Daemon
```bash
cd Inet-ZclockID/scripts
SYSVOL_PATH="/tmp/test_sysvol" python3 zclock-sysvold.py
```

---

## Testbed Deployment Blueprint (Dell PowerEdge R630 `192.168.1.40`)
* **Host Hypervisor:** VMware ESXi 6.7 (`192.168.1.40`)
* **Guest VM:** Ubuntu 24.04 / 26.04 LTS (2 vCPU, 4GB RAM, 40GB thin disk)
* **IP Address:** `192.168.1.45/24` (Gateway `192.168.1.1`)

