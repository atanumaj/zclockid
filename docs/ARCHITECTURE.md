# ZclockID System Architecture Specification

## 1. System Architecture Overview

ZclockID is structured as an appliance where core directory services, encrypted DNS, enterprise RADIUS, identity federation, and headless management operate as coordinated, modular systemd services.

```mermaid
flowchart TD
    subgraph Client_Access["Client Access Tier"]
        WinClient["Windows Workstations & RSAT\n(Port 53, 88, 135, 389, 445)"]
        WiFiClient["802.1X Wi-Fi APs & VPNs\n(UDP 1812 / 1813)"]
        WebClient["Web Browsers & Cloud Apps\n(HTTPS Port 443)"]
        NMSClient["Network Monitoring / PRTG\n(SNMP UDP 161)"]
    end

    subgraph Ingress_Layer["Ingress & Multiplexing Tier (Port 443)"]
        Proxy["Appliance Ingress Proxy (Nginx / HAProxy)\n• /api/v1/* -> REST API\n• /auth/* -> Keycloak SSO\n• /dns-query -> DoH Engine\n• / -> HTML5 Web Console"]
    end

    subgraph Core_Directory["Active Directory Core Engine"]
        SambaDC["Samba 4 AD DC Service\n• KDC / Kerberos (Port 88, 464)\n• LDAP / LDAPS (Port 389, 636)\n• RPC Server (Port 135, Dynamic)\n• SMB File Sharing (Port 445)\n• DRS Replication Engine"]
        SamLDB[("Samba SAM LDB Database\n/var/lib/samba/private/sam.ldb")]
    end

    subgraph DNS_Subsystem["DNS Engine (BIND9 DLZ)"]
        BIND9["BIND 9.18+ Service\n• Standard DNS (Port 53 UDP/TCP)\n• Native DoH Listener\n• DLZ Driver (dlz_bind9.so)\n• GSS-TSIG Dynamic DNS"]
    end

    subgraph Network_Access["Network Access Control (FreeRADIUS)"]
        FR3["FreeRADIUS 3.2 Service\n• EAP-PEAP / MS-CHAPv2\n• winbind ntlm_auth helper\n• LDAPS group membership check\n• RFC 3580 Dynamic VLANs"]
    end

    subgraph Sysvol_Engine["Sysvol Replication & NTACL Engine"]
        SysvolFS["Sysvol Filesystem\n/var/lib/samba/sysvol/"]
        SysvolDaemon["zclock-sysvold Service\n• Inotify Filesystem Watcher\n• Syncthing / rsync -XA Transport\n• Auto 'samba-tool ntacl sysvolreset'"]
    end

    subgraph Identity_SSO["Modern Identity & SSO (Keycloak)"]
        KC["Keycloak IdP Engine\n• SAML 2.0 Identity Provider\n• OpenID Connect (OIDC) & JWT\n• Kerberos SPNEGO Desktop SSO\n• LDAP User Federation to Samba"]
    end

    subgraph Management_API["Headless Management & Telemetry"]
        API["ZclockID FastAPI Service\n• RESTful API (Port 8000)\n• OpenAPI / Swagger Docs\n• Python samba-tool bindings"]
        GUI["HTML5 / Vue 3 Web Console\n• Appliance Health & Metrics\n• First-time Setup Wizard\n• DRS Replication Topology"]
        SNMP["SNMP & Telemetry Agent\n• OID Extensions for AD/DRS\n• Prometheus Metrics Exporter"]
    end

    %% Client Connections
    WinClient -->|SMB / Kerberos / RPC / DNS| SambaDC
    WinClient -->|DNS UDP/TCP 53| BIND9
    WiFiClient -->|RADIUS Auth/Acct| FR3
    WebClient -->|HTTPS 443| Proxy
    NMSClient -->|SNMP UDP 161| SNMP

    %% Ingress Proxy Routing
    Proxy -->|Proxy /dns-query| BIND9
    Proxy -->|Proxy /auth| KC
    Proxy -->|Proxy /api/v1| API
    Proxy -->|Static Frontend| GUI

    %% Internal Interconnections
    SambaDC <-->|Direct DLZ Hook| BIND9
    SambaDC --- SamLDB
    FR3 -->|ntlm_auth pipe| SambaDC
    FR3 -->|LDAPS Group Query| SambaDC
    KC -->|LDAPS & Kerberos| SambaDC
    SysvolDaemon <-->|File Sync & ACL Reset| SysvolFS
    API -->|Local UNIX CLI / Bindings| SambaDC
    API -->|Inspect & Control| SysvolDaemon
    API -->|Manage Clients| FR3
    SNMP -->|Poll Replication & Sessions| SambaDC
```

---

## 2. Ingress & Port Multiplexing Strategy

Because an enterprise appliance commonly exposes multiple HTTP-based services on standard TLS port `443`, ZclockID utilizes an internal reverse proxy (or native BIND path handling) to prevent socket collisions:

```
https://<appliance-fqdn>/
│
├── /dns-query                  ──► BIND 9.18 Native HTTP/DoH Listener (or dnsdist)
├── /api/v1/                    ──► ZclockID FastAPI Backend (localhost:8000)
├── /docs                       ──► Swagger OpenAPI Documentation
├── /auth/                      ──► Keycloak Modern SSO / SAML / OIDC (localhost:8080)
└── /* (root / assets)          ──► HTML5 Appliance Dashboard & Reporting UI
```

All non-HTTP directory protocols bind directly to standard dedicated network ports with zero proxy overhead.

---

## 3. Detailed Network Port Allocation Matrix

| Service | Port | Protocol | Scope | Direction | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DNS** | `53` | UDP & TCP | LAN / WAN | Inbound | Standard Active Directory DNS resolution |
| **Kerberos KDC** | `88` | UDP & TCP | LAN | Inbound | User authentication and Kerberos Ticket Granting (TGT) |
| **NTP** | `123` | UDP | LAN | Inbound | AD time synchronization (`chrony` with MS-SNTP signing) |
| **RPC Endpoint Mapper** | `135` | TCP | LAN | Inbound | RPC service resolution (DRS, RSAT, SAMR) |
| **NetBIOS Name / Session** | `137-139` | UDP / TCP | LAN | Inbound | Legacy NetBIOS name resolution and browsing |
| **LDAP** | `389` | TCP & UDP | LAN | Inbound | Active Directory directory queries & dynamic DNS |
| **Active Directory Web (DoH/GUI/SSO)**| `443` | TCP | LAN / WAN | Inbound | DNS-over-HTTPS, REST API, Web Console, Keycloak |
| **SMB (Server Message Block)** | `445` | TCP | LAN | Inbound | GPO download, Netlogon scripts, IPC$ RPC transport |
| **Kerberos Password (kpasswd)** | `464` | UDP & TCP | LAN | Inbound | Domain password change protocol |
| **LDAPS (LDAP over SSL)** | `636` | TCP | LAN | Inbound | Secure directory queries & Keycloak/RADIUS binding |
| **Global Catalog (GC)** | `3268` | TCP | LAN | Inbound | Forest-wide directory queries |
| **Global Catalog SSL** | `3269` | TCP | LAN | Inbound | Encrypted forest-wide directory queries |
| **FreeRADIUS Auth** | `1812` | UDP | LAN | Inbound | 802.1X Access-Request authentication |
| **FreeRADIUS Accounting**| `1813` | UDP | LAN | Inbound | RADIUS session start/stop/interim accounting |
| **Sysvol Sync (Syncthing)** | `22000` | TCP | DC-to-DC | Mutual | Encrypted P2P Sysvol replication |
| **Sysvol Sync Discovery** | `21027` | UDP | DC-to-DC | Mutual | Local broadcast discovery between DCs |
| **SNMP Daemon** | `161` | UDP | Mgmt LAN | Inbound | SNMP appliance telemetry |
| **Prometheus Exporter** | `9100` | TCP | Mgmt LAN | Inbound | Node and Samba metrics scraping |
| **RPC Dynamic Range** | `49152-65535` | TCP | LAN / Inter-DC | Mutual | High-port dynamic RPC for DRS replication & RSAT |

---

## 4. Authentication & Data Flows

### 4.1. Enterprise 802.1X Authentication Flow (FreeRADIUS + Samba AD)

```mermaid
sequenceDiagram
    autonumber
    actor Client as Wi-Fi / VPN Client
    participant AP as Switch / Wireless AP (NAS)
    participant FR as FreeRADIUS 3.2
    participant WB as Samba Winbind (ntlm_auth)
    participant KDC as Samba KDC / sam.ldb

    Client->>AP: Connects via 802.1X (EAPOL-Start)
    AP->>Client: EAP-Request / Identity
    Client->>AP: EAP-Response / Outer Identity
    AP->>FR: RADIUS Access-Request (UDP 1812)
    FR->>Client: Establishes PEAP TLS Tunnel (Phase 1)
    FR->>Client: EAP-MS-CHAPv2 Challenge (Phase 2 inside TLS)
    Client->>FR: EAP-MS-CHAPv2 Response (User + Hash)
    FR->>WB: Invokes ntlm_auth helper with challenge & response
    WB->>KDC: Validates NT hash against sam.ldb
    KDC-->>WB: Credentials Valid (User Authenticated)
    WB-->>FR: Returns Success + User NT-Key
    FR->>KDC: Queries LDAPS for user's memberOf groups
    KDC-->>FR: Returns group membership (e.g. WiFi-Corporate)
    FR-->>AP: RADIUS Access-Accept + Dynamic VLAN (Tunnel-Private-Group-Id = 50)
    AP-->>Client: 802.1X EAP-Success, port/SSID opened on VLAN 50
```

---

### 4.2. Web SSO & Kerberos SPNEGO Flow (Keycloak + Samba AD)

```mermaid
sequenceDiagram
    autonumber
    actor User as Domain-Joined PC (Browser)
    participant App as Web Application (SaaS / Portal)
    participant KC as Keycloak IdP (ZclockID)
    participant KDC as Samba Kerberos KDC

    User->>App: Navigates to application
    App->>User: Redirects to Keycloak with SAML / OIDC request
    User->>KC: Requests login page (HTTPS 443)
    KC->>User: 401 Unauthorized (WWW-Authenticate: Negotiate)
    Note over User: Browser detects trusted internal domain FQDN
    User->>KDC: Requests Kerberos Service Ticket for HTTP/keycloak.corp
    KDC-->>User: Issues Kerberos Service Ticket (TGS)
    User->>KC: Re-submits request with Authorization: Negotiate <ticket>
    KC->>KC: Decrypts ticket using keycloak.keytab
    KC->>KDC: Validates user attributes via LDAPS
    KC-->>User: Issues SAML Assertion / OIDC JWT Token
    User->>App: Submits Assertion / Token to Application
    App-->>User: User logged in seamlessly without typing password!
```

---

### 4.3. Multi-DC Sysvol & NTACL Replication Flow

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Sysadmin via RSAT (gpmc.msc)
    participant DC1 as Primary DC (PDC)
    participant DC1_Sync as DC1 zclock-sysvold
    participant DC2_Sync as Secondary DC (BDC)
    participant DC2_Tool as DC2 samba-tool ntacl

    Admin->>DC1: Edits or creates Group Policy Object (GPO)
    Note over DC1: GPO files written to /var/lib/samba/sysvol/...
    DC1_Sync->>DC1_Sync: inotify detects file change event
    DC1_Sync->>DC2_Sync: Replicates file payload & POSIX permissions (Syncthing / rsync -XA)
    Note over DC2_Sync: New GPO files written to DC2 sysvol
    DC2_Sync->>DC2_Sync: inotify detects incoming batch completion
    DC2_Sync->>DC2_Tool: Triggers debounced 'samba-tool ntacl sysvolreset'
    DC2_Tool->>DC2_Tool: Rebuilds Windows NT Security Descriptors on all GPOs
    Note over DC1,DC2_Sync: Both DCs maintain identical files and flawless Windows NTACLs!
```

---

## 5. Filesystem Layout & Storage Allocation

| Path | Purpose | Backup Priority |
| :--- | :--- | :--- |
| `/etc/samba/smb.conf` | Core Samba Active Directory configuration | High |
| `/var/lib/samba/private/` | AD database (`sam.ldb`), secrets, Kerberos keytabs | Critical (Full AD snapshot) |
| `/var/lib/samba/sysvol/` | Sysvol share: GPOs, logon scripts, policies | Critical (Synced across DCs) |
| `/etc/bind/named.conf*` | BIND9 DLZ & DoH options and zones | High |
| `/etc/freeradius/3.0/` | RADIUS NAS clients, inner-tunnel, mschap, ldap configs | High |
| `/etc/zclockid/` | ZclockID appliance configuration & API secrets | High |
| `/opt/zclockid/api/` | Headless REST API backend codebase (FastAPI) | Managed by updater |
| `/opt/zclockid/web/` | HTML5 Web Dashboard static build | Managed by updater |
| `/var/log/zclockid/` | Structured appliance telemetry & audit logs | Rotated via logrotate |

