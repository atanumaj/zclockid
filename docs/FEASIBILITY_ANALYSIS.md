# ZclockID: Feasibility & Architectural Analysis

**Product Name:** ZclockID (Inet-ZclockID)  
**Target Appliance:** Purpose-Built Open-Source Active Directory Domain Controller & Identity Management Appliance  
**Target Base Operating System:** Ubuntu Linux LTS (Ubuntu 24.04.1 LTS / 26.04 LTS)  
**Hardware / Hypervisor Testbed:** Dell PowerEdge R630 (`192.168.1.40` ESXi 6.7 / KVM)  
**Target Market:** SMEs, Managed Service Providers (MSPs), Enterprise Branch Offices, and Customer Cloud Deployments  

---

## 1. Executive Summary

Organizations seeking an on-premises or private-cloud Active Directory Domain Controller without paying exorbitant Microsoft Windows Server CALs have historically turned to Linux solutions such as **Zentyal Server**. However, Zentyal is hampered by major architectural flaws:
1. **Monolithic Bloat:** It forces users into an all-in-one bundle containing a legacy firewall, Squid proxy, Antivirus (ClamAV), DHCP, and Mail, none of which belong on a pure Domain Controller.
2. **Brittle Configuration Model:** It relies on an aging Perl/Catalyst codebase (originating in 2004) that maintains an internal Redis state and rewrites `/etc` configuration files whenever changes are applied, frequently leading to service outages and configuration drift.
3. **Unreliable Sysvol Replication:** Zentyal's multi-DC Sysvol sync frequently drops or corrupts Windows NT Access Control Lists (`security.NTACL`), causing Group Policy failures on Windows clients.
4. **No Modern Identity & Modern Protocols:** Zentyal lacks native modern identity capabilities such as DNS-over-HTTPS (DoH), SAML 2.0 / OpenID Connect (OIDC) web federation, and a comprehensive headless REST API.

**ZclockID** is conceived as a **laser-focused, purpose-built Active Directory Domain Controller and Identity & Access Management (IAM) appliance**. It strips away the firewall, mail, and proxy clutter, delivering a hardened, rock-solid core composed of:
- **Samba AD DC (Latest Stable & Fully Patched):** Enterprise KDC, Kerberos, LDAP, Winbind, and Directory Replication Services (DRS).
- **BIND9 DLZ with Native DNS-over-HTTPS (DoH):** Authoritative AD DNS directly querying `sam.ldb` with encrypted DoH capabilities.
- **FreeRADIUS Engine:** Transparent 802.1X Wi-Fi / VPN / Switch authentication via Samba `ntlm_auth` and LDAP dynamic VLAN assignment.
- **Bi-Directional Sysvol Replication with NTACL Self-Healing:** Synchronized via Syncthing/rsync with automated event-driven NTACL preservation.
- **Headless REST API:** 100% headless control via FastAPI with OpenAPI documentation.
- **Keycloak Web Identity Federation:** Native SAML 2.0, OIDC, and JWT issuance backed by Samba Kerberos/LDAP.
- **Lightweight HTML5 Web Console:** Telemetry dashboard, appliance management, and reporting, designed to seamlessly coexist with Microsoft RSAT (`dsa.msc`, `gpmc.msc`).

---

## 2. Technical Feasibility Matrix

| Engine / Requirement | Feasibility Rating | Proven Open-Source Component | Key Implementation Architecture | Technical Risks & Mitigations |
| :--- | :---: | :--- | :--- | :--- |
| **Samba AD DC** | **EXCELLENT (10/10)** | Samba 4.19 / 4.20+ (`samba-ad-dc`) | Native DRSUAPI directory replication, Kerberos KDC, SMB3, Winbind. | *Risk:* Upstream schema compatibility.  <br>*Mitigation:* Stick to standard AD Functional Level 2012R2/2016; test against RSAT. |
| **BIND9 DLZ + DoH** | **HIGH (9/10)** | BIND 9.18+ (`bind9-dlz`) | Dynamic Zone loading (`dlz_bind9_*.so`) with native `http` & `tls` DoH endpoints (`/dns-query`). | *Risk:* Port 443 conflict between DoH and Web GUI.  <br>*Mitigation:* Multiplex via reverse proxy (Nginx/HAProxy) or dedicate DoH URI paths. |
| **FreeRADIUS transparent AD** | **EXCELLENT (10/10)** | FreeRADIUS 3.2+ (`freeradius`) | PEAP-MSCHAPv2 via Samba's `ntlm_auth` helper binary; LDAPS for user search & RFC 3580 dynamic VLAN assignment. | *Risk:* NTLM deprecation or Winbind pipe permissions.  <br>*Mitigation:* Add `freerad` user to `winbindd_priv` group; enforce `mschapv2-and-ntlmv2-only`. |
| **Sysvol Bi-Directional Sync** | **FEASIBLE (8.5/10)** | Syncthing / `rsync -XA` + `inotify` daemon | Event-driven file payload sync combined with automated `samba-tool ntacl sysvolreset` reconciliation. | *Risk:* Dropped Windows extended attributes (`security.NTACL`).  <br>*Mitigation:* Automated background reconciliation timer & inotify trigger. |
| **SNMP & Telemetry** | **EXCELLENT (10/10)** | Net-SNMP 5.9+ & Prometheus Exporter | Custom Net-SNMP `extend` OIDs querying DRS replication status, active sessions, and RADIUS stats. | *Risk:* SNMP query latency on large directories.  <br>*Mitigation:* Daemonized telemetry caching script (`/dev/shm/ad_telemetry.json`). |
| **Headless REST API** | **EXCELLENT (10/10)** | Python 3.12+ FastAPI & Pydantic | RESTful API exposing `/domain`, `/users`, `/groups`, `/sysvol`, `/radius`, and `/system` endpoints. | *Risk:* Direct LDAP modifications bypassing Samba validation.  <br>*Mitigation:* Leverage `samba-tool` Python library / CLI bindings internally. |
| **Keycloak SAML / OIDC** | **HIGH (9/10)** | Keycloak 24+ (Quarkus runtime) | Native LDAP User Federation + Kerberos SPNEGO Desktop Single Sign-On. | *Risk:* Java memory consumption.  <br>*Mitigation:* Keycloak Quarkus container tuned for 512MB RAM; or lightweight alternative (Authentik/Authelia). |
| **Lightweight HTML5 GUI** | **EXCELLENT (10/10)** | Vue 3 / HTML5 + Tailwind CSS | Single Page App focusing on appliance setup, telemetry, replication map, and reporting. | *Risk:* Feature creep trying to duplicate RSAT.  <br>*Mitigation:* Strictly limit GUI to appliance health/telemetry; let RSAT handle deep GPO/OUs. |

---

## 3. Comparative Analysis: Zentyal vs. ZclockID

| Dimension | Legacy Zentyal Server | ZclockID Appliance |
| :--- | :--- | :--- |
| **Design Philosophy** | "Jack-of-all-trades" monolithic small-business server. Bundles Firewall, Gateway, Mail, Antivirus, DHCP, Proxy, and Samba. | **Purpose-Built Enterprise IAM Appliance.** Exclusively handles Active Directory, DNS, RADIUS, and SSO. |
| **Software Architecture** | Old Perl (Catalyst framework) + Redis. Monolithic configuration templates that overwrite system files. | **Modern Python 3 / FastAPI + modular systemd services.** Decoupled configurations; no blanket config overwrites. |
| **Hardware Footprint** | 4 GB - 8 GB RAM minimum due to ClamAV, SpamAssassin, Squid, and Perl daemons. | **1.5 GB - 2 GB RAM baseline.** Lean, high-density VM suitable for branch offices and edge servers. |
| **Sysvol Replication** | Notoriously fragile. Frequently causes Windows GPO Access Denied (`0x80070005`) errors across secondary DCs. | **Engineered Sysvol Daemon.** Pairs real-time file sync with automatic NTACL repair and health checks. |
| **Network Access Control** | Basic RADIUS module with limited troubleshooting or dynamic VLAN assignment. | **Native Enterprise 802.1X FreeRADIUS.** Full support for MS-CHAPv2, PEAP, and AD-driven Dynamic VLAN assignment. |
| **Modern Web Protocols** | Plaintext DNS (port 53) only. No modern encryption. | **Native DNS-over-HTTPS (DoH)** and DNS-over-TLS (DoT) via BIND 9.18+. |
| **Cloud & Web SSO** | None. Pure legacy Kerberos/NTLM. Cannot serve SAML 2.0 or OIDC to modern cloud SaaS. | **Integrated SAML 2.0 & OpenID Connect IdP (Keycloak).** Kerberos SPNEGO provides seamless zero-touch SSO for domain PCs. |
| **Automation & DevOps** | Virtually nonexistent. No REST API; changes require web UI clicks or hacky Perl scripts. | **100% Headless REST API** with OpenAPI (Swagger) specifications, scriptable via Ansible, Terraform, or curl. |
| **Management Model** | Confusing UI trying to manage network firewalls and domain users in the same interface. | **Clean Division of Responsibility:** Native Microsoft RSAT for directory management; sleek HTML5 Web Console for appliance telemetry and operations. |

---

## 4. Deep-Dive Engine Feasibility

### 4.1. Samba Active Directory Domain Controller
- **Feasibility:** Fully validated in enterprise production.
- **Base Version:** Samba 4.19.x / 4.20.x on Ubuntu LTS.
- **Directory Replication (DRS):** Samba's built-in DRS engine implements Microsoft MS-DRSR over RPC. Multi-DC replication between ZclockID nodes (or between Windows Server and ZclockID) is native and battle-tested for:
  - `Schema` partition
  - `Configuration` partition
  - `Domain` partition
  - `DomainDnsZones` and `ForestDnsZones` partitions
- **FSMO Roles:** ZclockID supports full FSMO role transfer (`Schema`, `Domain Naming`, `PDC Emulator`, `RID Master`, `Infrastructure Master`) via `samba-tool fsmo transfer`.

### 4.2. BIND9 DLZ with DNS-over-HTTPS (DoH)
- **Feasibility:** Highly viable and modern.
- **Mechanism:** BIND 9.18+ introduces native HTTP/2 and TLS listeners (`http` and `tls` blocks in `named.conf`).
- **DLZ Integration:** The Samba DLZ driver (`dlz_bind9_18.so`) hooks directly into `/var/lib/samba/private/dns.keytab` and `sam.ldb`. When Windows clients register Dynamic DNS updates (A, PTR, SRV), BIND writes them directly to the directory.
- **Encrypted DNS:** External clients, mobile devices, and secure browsers can query the same AD zones via DoH (`https://<dc-ip>/dns-query`) while internal legacy domain PCs query standard UDP/TCP port 53.
- **Reverse Proxy Architecture:** By placing an ultra-lightweight reverse proxy (or configuring BIND on dedicated ports) at ingress, port 443 can serve the Web Console, the REST API, Keycloak, and `/dns-query` concurrently.

### 4.3. FreeRADIUS 802.1X Transparent Authentication
- **Feasibility:** Standard enterprise industry practice.
- **Integration Flow:**
  1. Client sends EAP-PEAP outer identity.
  2. Inner phase executes MS-CHAPv2.
  3. FreeRADIUS invokes `/usr/bin/ntlm_auth --request-nt-key --domain=CORP --username=%{mschap:User-Name} ...` against local Samba Winbind.
  4. Winbind authenticates against the local Samba KDC / NT hash without exposing passwords.
  5. Upon success, FreeRADIUS queries local LDAPS to retrieve the user's `memberOf` groups and injects RFC 3580 Dynamic VLAN IDs (e.g. Corporate VLAN 50, Guest VLAN 60).

### 4.4. Sysvol Synchronization & NTACL Preservation
- **The Problem:** DRS replicates the directory database, but `/var/lib/samba/sysvol/` requires filesystem synchronization. Standard file synchronization tools (like naive rsync or Unison) frequently strip or mangle Windows NTACL extended attributes (`security.NTACL`), breaking Group Policy (`gpmc.msc`).
- **The ZclockID Solution:**
  1. **Replication Transport:** Syncthing or bidirectional `rsync -XA` over SSH (preserves extended attributes and POSIX ACLs).
  2. **Automated NTACL Self-Healing:** An event-driven daemon (`zclock-sysvold`) utilizes Linux `inotify` on `/var/lib/samba/sysvol`. When policies are created or modified from RSAT, the daemon automatically runs `samba-tool ntacl sysvolreset` in a debounced background worker, guaranteeing zero ACL degradation across all domain controllers.

### 4.5. Headless REST API
- **Feasibility:** High performance and modern developer ergonomics.
- **Technology:** FastAPI (Python 3.12) running under Uvicorn with systemd management.
- **Scope:**
  - System status, CPU/RAM/Disk metrics.
  - Domain status: FSMO role holders, DRS replication partner matrix, replication failure counts.
  - User & Group lifecycle: Quick provisioning, password resets, account locking/unlocking.
  - DNS management: Zone queries, record creation.
  - Sysvol health: Force synchronization, trigger ACL resets.
  - FreeRADIUS NAS client management: Add/edit network switches and access points.
  - Backup & Disaster Recovery: Automated triggers for `samba-tool domain backup`.

### 4.6. Modern Web SSO: Keycloak (SAML 2.0 & OIDC)
- **Feasibility:** Enterprise-grade and widely supported.
- **Integration:** Keycloak connects to local Samba AD via LDAP User Federation (`ldaps://127.0.0.1:636`).
- **Desktop SSO:** Configured with Kerberos SPNEGO. Domain-joined workstations experience zero-prompt transparent logins when accessing web applications.
- **Cloud Federation:** ZclockID becomes the local IdP for Google Workspace, Microsoft 365, AWS IAM Identity Center, pfSense Captive Portal, and internal company web portals.

---

## 5. Commercialization & Packaging Strategy

ZclockID can be packaged and distributed across several tiers:

### 5.1. Distribution Formats
1. **Virtual Appliance (Turnkey OVA / OVF / VMDK):**
   - Pre-configured, hardened Ubuntu LTS base with ZclockID engines pre-installed.
   - Deployable in <5 minutes on VMware ESXi, Proxmox VE, Microsoft Hyper-V, and Nutanix.
2. **Cloud-Init ISO / Bare-Metal Installer:**
   - Automated unattended installer script for Dell PowerEdge, HP ProLiant, Supermicro, or custom servers.
3. **Containerized / Microservices Version:**
   - Docker Compose / Podman stack for specific lightweight deployments (Keycloak, API, GUI).

### 5.2. Customer Value Proposition & Sales Model
- **Zero Microsoft CAL Licensing Fees:** A typical 50-seat business pays $1,500+ for Windows Server Standard plus $40/user CAL ($3,500 total). ZclockID provides full Active Directory functionality with zero CAL licensing costs.
- **MSP Multi-Tenant Management:** Managed Service Providers can manage dozens of client ZclockID appliances via the Headless REST API and automated telemetry.
- **Commercial Support & Update Subscription:**
  - Community Edition: Open-source, self-hosted.
  - Enterprise Subscription: Automated security updates, backup management, SLA support, and proprietary multi-site orchestrator.

---

## 6. Development & Deployment Roadmap

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ZCLOCKID ROADMAP MILESTONES                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
    ┌───────────────────────────────┴───────────────────────────────┐
    ▼                                                               ▼
[Phase 1: Core Engine]                                      [Phase 2: Network & Access]
• Samba 4 AD DC baseline                                    • BIND 9.18 DLZ + Native DoH
• Automated domain provisioning                             • FreeRADIUS 802.1X integration
• DRS multi-DC replication                                  • `ntlm_auth` & Dynamic VLANs
• Sysvol Syncthing + NTACL healer                           • Net-SNMP AD telemetry extensions
    │                                                               │
    └───────────────────────────────┬───────────────────────────────┘
                                    │
    ┌───────────────────────────────┴───────────────────────────────┐
    ▼                                                               ▼
[Phase 3: Management & API]                                 [Phase 4: Identity & GUI]
• FastAPI headless REST backend                             • Keycloak SAML 2.0 / OIDC IdP
• Automated OpenAPI Swagger docs                            • Kerberos SPNEGO Desktop SSO
• Linux systemd daemonization                               • Lightweight HTML5 Web Console
• RSAT compatibility verification                           • Turnkey OVA/VMDK appliance build
```

---

## 7. Conclusion & Recommendation

**Verdict: HIGHLY FEASIBLE AND STRATEGICALLY ADVANTAGEOUS (GO).**

Building ZclockID is not only technically feasible using mature, rock-solid open-source engines, but it directly addresses the critical pain points that have plagued Zentyal for over a decade. By eliminating the bloated firewall/proxy/mail dependencies and focusing purely on Active Directory, encrypted DNS, enterprise RADIUS, modern web SSO, and headless API management, ZclockID will deliver a superior, highly commercially viable enterprise identity appliance.

