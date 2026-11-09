# ZclockID™ Software License Agreement & Terms of Use

**Copyright © 2026 Atanu Majumdar (@atanumaj). All Rights Reserved.**  
**Original Author & Architect:** Atanu Majumdar (`https://github.com/atanumaj`)  
**Official Repository:** `https://github.com/atanumaj/zclockid`

IMPORTANT: PLEASE READ THIS SOFTWARE LICENSE AGREEMENT CAREFULLY BEFORE DOWNLOADING, 
INSTALLING, OR USING THE ZCLOCKID ENTERPRISE APPLIANCE SOFTWARE.

---

## 1. Proprietary Software Grant & Scope

This License Agreement governs your deployment and use of the ZclockID appliance management 
software and proprietary components, including:
* The ZclockID REST API Management Subsystem (`api/`)
* The ZclockID Web Management Console & Glassmorphism UI (`web/`)
* The `zclock-sysvold` Sysvol Replication & Windows NTACL Self-Healing Engine
* The Captive Portal & Dynamic Bandwidth QoS Policy Controllers
* The Ed25519 Cryptographic Licensing & Capacity Enforcement Subsystem

All copyright, intellectual property rights, trademarks, and title in and to the ZclockID 
software remain exclusively with **Atanu Majumdar (@atanumaj)** and authorized corporate successors.

---

## 2. Licensing Tiers & Capacity Usage

### A. Community Free Tier (Up to 200 Users)
ZclockID grants you a non-exclusive, non-transferable, royalty-free, perpetual license to deploy 
and operate the appliance for internal business, educational, non-profit, or homelab environments 
for up to **two hundred (200) Active Directory user accounts** without acquiring a commercial license key.

### B. Enterprise Commercial Subscription (Above 200 Users)
Deployments hosting more than two hundred (200) Active Directory user accounts require a valid, 
cryptographically signed ZclockID Enterprise Commercial License certificate (`zclockid.lic`) issued 
directly by the copyright holder or authorized distributors.

---

## 3. License Restrictions & Fair Use

Except as expressly permitted by this Agreement or mandatory applicable law, you may not:
1. Reverse engineer, decompile, patch, or tamper with the cryptographic verification subsystem 
   (`api/core/license.py`) or modify the 200-user capacity threshold.
2. Generate, forge, or distribute unauthorized digital license files (`*.lic`).
3. Sublicense, lease, rent, or distribute the proprietary management interface as a standalone 
   commercial product without prior written consent from the author.
4. Remove, obscure, or alter any copyright notices, trademarks, or author fingerprints from 
   the source code or user interface.

---

## 4. Open Source & Third-Party Components (Aggregation Model)

The ZclockID appliance operates as an integrated management appliance that orchestrates several 
standalone, upstream open-source daemons and operating system packages. In accordance with Section 5 
of the GNU General Public License (GPLv3) and standard "mere aggregation" jurisprudence, these 
independent components run as separate system processes and are governed by their respective licenses:

| Component | Upstream Project | License | Function / Architecture |
| :--- | :--- | :--- | :--- |
| **Samba Core** | Samba Team | **GNU GPLv3+** | Active Directory Domain Controller, Kerberos KDC, LDAP/S, DRS |
| **BIND 9** | Internet Systems Consortium (ISC) | **MPL 2.0** | DLZ Domain Name System & encrypted DNS-over-HTTPS (DoH) |
| **FreeRADIUS** | FreeRADIUS Project | **GNU GPLv2** | 802.1X Network Access Server, MS-CHAPv2 & EAP |
| **Chrony** | Chrony Project | **GNU GPLv2** | Authenticated NTP time synchronization |
| **Nginx** | F5 / Nginx Team | **2-Clause BSD** | Reverse proxy, TLS termination, HTTP/2 DoH multiplexer |
| **Linux Kernel** | Linux Foundation / Ubuntu | **GNU GPLv2** | Host operating system kernel |
| **FastAPI** | Sebastián Ramírez (tiangolo) | **MIT License** | REST API framework |
| **Tailwind CSS** | Tailwind Labs | **MIT License** | Console stylesheet framework |
| **FontAwesome** | Fonticons, Inc. | **SIL OFL 1.1 / MIT** | Console UI iconography |

Nothing in this Agreement restricts, limits, or supersedes your rights under the terms and conditions 
of any applicable third-party open-source license. Source code for unmodified upstream packages is 
accessible from standard Ubuntu LTS repositories or official upstream mirrors.

---

## 5. Disclaimer of Warranty & Limitation of Liability

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING 
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, 
AND NONINFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDER, AUTHOR, OR CONTRIBUTORS BE LIABLE 
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING 
LOSS OF DATA, LOSS OF PROFITS, BUSINESS INTERRUPTION, OR PROCUREMENT OF SUBSTITUTE SERVICES) 
ARISING IN ANY WAY OUT OF THE USE OR INABILITY TO USE THIS SOFTWARE.
