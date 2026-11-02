# ZclockID Commercialization & Go-To-Market Strategy

## 1. Value Proposition & Customer ROI

The primary business problem ZclockID solves is **the exorbitant cost and licensing complexity of Microsoft Windows Server Active Directory and Client Access Licenses (CALs)** for Small and Medium Enterprises (SMEs), Branch Offices, and Managed Service Providers (MSPs).

### Cost Comparison: 50-User Office (3-Year TCO)

| Expense Item | Traditional Microsoft Stack | Zentyal Server | ZclockID Commercial Appliance |
| :--- | :--- | :--- | :--- |
| **Server OS License** | $1,069 (Windows Server Standard) | €295 - €890 / year subscription | **$0 (Open Source Core)** |
| **Client Access Licenses (CALs)** | $2,700 (50 users @ ~$54/CAL) | Included in license tier | **$0 (Zero CALs required)** |
| **802.1X Enterprise RADIUS** | Network Policy Server (NPS) CALs | Basic (manual Perl config) | **Built-in FreeRADIUS 3** |
| **Modern Cloud SSO (SAML/OIDC)** | AD FS / Microsoft Entra ID P1 ($6/mo/user = $3,600/yr) | Not supported | **Built-in Keycloak IdP** |
| **Encrypted Modern DNS (DoH)** | Third-party / Windows 11 only | Not supported | **Built-in BIND9 Native DoH** |
| **3-Year Estimated TCO** | **$7,500 - $14,000+** | **€1,500 - €2,700** | **$900 - $1,500 (Optional Support)** |
| **Customer Savings** | — | ~60% | **~85% - 90% Savings** |

---

## 2. Customer Packaging & Distribution Models

### A. Turnkey Virtual Appliance (OVA / OVF / VMDK)
* **Target Platforms:** VMware ESXi, Proxmox VE, Hyper-V, Nutanix AHV, KVM.
* **Format:** Pre-built, security-hardened minimal Ubuntu Linux virtual machine image.
* **Onboarding Experience:**
  1. Customer imports OVA into hypervisor.
  2. Boots in under 60 seconds with DHCP IP.
  3. Administrator browses to `https://<ip>/` and is greeted by the ZclockID Initial Setup Wizard:
     - Step 1: Set Admin Password & FQDN (`corp.customer.com`).
     - Step 2: Choose Role: **New Forest Primary DC** or **Join Existing Forest (Secondary DC)**.
     - Step 3: Network Settings (Static IP, Gateway, Upstream DNS).
     - Step 4: Click "Provision". Done in 3 minutes!

### B. Bare-Metal & Cloud-Init ISO Installer
* For customers deploying dedicated physical appliances (1U Dell PowerEdge, Supermicro, HP MicroServer, or Intel NUC).
* Unattended ISO installation with automatic disk partitioning, ext4 with xattr/ACL flags, and ZclockID bootstrap.

### C. Managed Service Provider (MSP) Multi-Tenant Fleet Edition
* MSPs can deploy ZclockID appliances across dozens of client networks.
* All appliances report health, DRS status, and telemetry back to a centralized MSP Fleet Portal via the Headless REST API and mTLS.

---

## 3. Product Roadmap & Phased Delivery

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ZCLOCKID RELEASE ROADMAP                        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
    ┌───────────────────────────────┴───────────────────────────────┐
    ▼                                                               ▼
[MVP 1: Core Appliance & Identity]                          [MVP 2: Advanced Access & Hotspot]
• Latest Samba 4 AD DC with DRS replication                 • Wi-Fi Hotspot Captive Portal RADIUS Engine
• BIND 9.18 DLZ + Native DNS-over-HTTPS (DoH)              • RADIUS Accounting integration with Web SSO
• FreeRADIUS 3.2 Enterprise 802.1X (PEAP-MSCHAPv2)          • Multi-Factor Authentication (OTP / TOTP / MFA)
• Bi-directional Sysvol Sync & NTACL Self-Healing           • Guest Voucher Generation & Bandwidth Quotas
• Nginx Unified Port 443 Ingress Proxy                      • Advanced Accounting Analytics & Session Tracking
• Headless REST Management API (FastAPI)                    • SMS Gateway & Email OTP Dispatchers
• Lightweight HTML5 Appliance Dashboard & Reporting         
• Automated Debian Package (.deb) & Single-Script Installer 
```

### MVP 1 (Current Focus) Scope:
* Hardened Samba AD DC with full Microsoft RSAT compatibility.
* BIND9 DLZ with native HTTP/2 DoH on `/dns-query`.
* Enterprise 802.1X RADIUS for company Wi-Fi (WPA2/WPA3-Enterprise) and 802.1X switch ports.
* Real-time Sysvol sync with automatic Windows NTACL preservation.
* Fast, lightweight Nginx ingress on Port 443.
* Complete Headless REST API with interactive Swagger documentation.

### MVP 2 (Planned Next) Scope:
* **Wi-Fi Hotspot Captive Portal:** Dynamic captive portal integration for guest Wi-Fi.
* **MFA / OTP Authentication:** Two-factor authentication (TOTP apps like Google Authenticator, SMS OTP, or Email OTP) before granting Wi-Fi access.
* **RADIUS Accounting & Web SSO:** Centralized session duration tracking, bandwidth accounting, and SSO session pairing.
* **Guest Self-Registration & Vouchers:** Time-limited and data-capped guest credentials generated via API or Web Console.

---

## 4. Product Tiers & Monetization Model

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ZCLOCKID PRODUCT TIERS                          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
    ┌───────────────────────────────┴───────────────────────────────┐
    ▼                                                               ▼
[Community Edition (CE)]                                    [Enterprise / MSP Edition]
• 100% Free & Open-Source                                   • Commercial Annual Subscription
• Unlimited users & workstations                            • Turnkey Virtual Appliance (OVA)
• Full Active Directory & RSAT                              • Automated Rolling Security Updates
• FreeRADIUS 802.1X Wi-Fi / VPN                             • Automated Cloud Offsite Backups
• BIND9 DoH Encrypted DNS                                   • Multi-Site Centralized Fleet Manager
• Community Forum Support                                   • 24/7 SLA & Direct Engineering Support
```

---

## 4. Hypervisor Testbed Blueprint (ESXi 6.7 on Dell PowerEdge R630 `192.168.1.40`)

The primary testbed will be deployed on the existing Dell PowerEdge R630 (`192.168.1.40`):

| VM Specification | Testbed Allocation | Minimum Production Allocation |
| :--- | :--- | :--- |
| **VM Name** | `zclockid-testbed-01` | `zclockid-prod-dc01` |
| **vCPU** | 2 vCPUs (Xeon E5-2630 v3) | 2 to 4 vCPUs |
| **RAM** | 4,096 MB (4 GB) | 4,096 MB (8 GB if Keycloak enabled) |
| **Disk** | 40 GB Thin Provisioned (VMFS) | 60 - 100 GB (ext4 with `user_xattr`) |
| **vSwitch Portgroup** | `VM Network` (VLAN 1 Server Infra) | Dedicated Server VLAN |
| **Static IP Address** | `192.168.1.45/24` | Primary VIP / Secondary IP |
| **Gateway** | `192.168.1.1` (pfSense CARP) | Site Gateway |
| **DNS Server** | `127.0.0.1`, `192.168.1.23` (Zentyal DC) | Localhost + Secondary DC |

