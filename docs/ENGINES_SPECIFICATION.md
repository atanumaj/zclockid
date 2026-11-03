# ZclockID Engine & Subsystem Technical Specifications

This document defines the low-level technical specifications, configuration parameters, and integration requirements for each core engine inside ZclockID.

---

## 1. Engine 1: Samba Active Directory Domain Controller

### 1.1. Package & Environment Baseline
* **Base Platform:** Ubuntu 24.04.1 LTS / 26.04 LTS (Kernel 6.8+).
* **Core Packages:** `samba`, `smbclient`, `winbind`, `libpam-winbind`, `libnss-winbind`, `krb5-user`, `acl`, `attr`, `chrony`.
* **Filesystem Prerequisites:** Root/Sysvol filesystem mounted with `user_xattr`, `acl`, and `barrier=1` (standard in ext4 and xfs on modern Ubuntu).

### 1.2. Baseline `smb.conf` Configuration Template
```ini
# /etc/samba/smb.conf
# ZclockID Active Directory Domain Controller Baseline

[global]
    netbios name = DC1
    realm = CORP.EXAMPLE.COM
    workgroup = CORP
    server role = active directory domain controller

    # DNS Backend configuration (delegated to BIND9 DLZ)
    server services = -dns
    dns forwarder = 1.1.1.1 8.8.8.8

    # Kerberos & Authentication parameters
    kerberos method = secrets and keytab
    ntlm auth = mschapv2-and-ntlmv2-only
    client ldap sasl wrapping = sign
    ldap server require strong auth = yes

    # Winbind configuration
    idmap_ldb:use rfc2307 = yes
    winbind enum users = yes
    winbind enum groups = yes
    winbind use default domain = yes

    # SMB Protocol Dialects
    server min protocol = SMB2_10
    client min protocol = SMB2_10

    # Logging
    log level = 1 auth_audit:3
    log file = /var/log/samba/%m.log
    max log size = 50000

    # NTP signing socket for Windows Time Service
    ntp signd socket directory = /var/lib/samba/ntp_signd

[sysvol]
    path = /var/lib/samba/sysvol
    read only = no

[netlogon]
    path = /var/lib/samba/sysvol/corp.example.com/scripts
    read only = no
```

### 1.3. Time Synchronization (`chrony` with MS-SNTP Signing)
Active Directory strictly rejects Kerberos tickets if clock skew exceeds 300 seconds (5 minutes). Windows domain clients synchronize time using signed MS-SNTP.
* **Socket Path:** `/var/lib/samba/ntp_signd`
* **Chrony Directive in `/etc/chrony/chrony.conf`:**
  ```text
  ntpsigndsocket /var/lib/samba/ntp_signd
  allow 192.168.0.0/16
  ```
* **Permissions:**
  ```bash
  sudo chown root:_chrony /var/lib/samba/ntp_signd
  sudo chmod 750 /var/lib/samba/ntp_signd
  ```

---

## 2. Engine 2: BIND9 DLZ with DNS-over-HTTPS (DoH)

### 2.1. Dynamic Link Zone (DLZ) Driver
Unlike flat file DNS, Samba AD DC stores DNS records inside the Active Directory partition `DC=DomainDnsZones,DC=corp,DC=example,DC=com` in `sam.ldb`. BIND9 accesses this database dynamically in real time via the DLZ module:
* Driver binary: `/usr/lib/x86_64-linux-gnu/samba/bind9/dlz_bind9_18.so`
* Kerberos Keytab for dynamic updates: `/var/lib/samba/private/dns.keytab`

### 2.2. BIND Configuration (`/etc/bind/named.conf.options`)
```named
// TLS & HTTP profiles for DNS-over-HTTPS (DoH)
tls doh-tls {
    key-file "/etc/bind/certs/privkey.pem";
    cert-file "/etc/bind/certs/fullchain.pem";
    ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";
};

http doh-http {
    endpoints { "/dns-query"; };
    listener-clients 500;
    streams-per-connection 100;
};

options {
    directory "/var/cache/bind";
    version "none";

    // Standard RFC DNS Listeners
    listen-on port 53 { any; };
    listen-on-v6 port 53 { any; };

    // Encrypted DNS-over-HTTPS (DoH) Listener
    listen-on port 443 tls doh-tls http doh-http { any; };

    // Query & Forwarding Policies
    allow-query { any; };
    allow-recursion { 127.0.0.1; 192.168.0.0/16; 10.0.0.0/8; };
    recursion yes;

    forwarders {
        1.1.1.1;
        8.8.8.8;
    };

    dnssec-validation auto;
    auth-nxdomain no;

    // Secure Dynamic DNS via Kerberos GSS-TSIG
    tkey-gssapi-keytab "/var/lib/samba/private/dns.keytab";
};
```

---

## 3. Engine 3: FreeRADIUS 802.1X Transparent Authentication

### 3.1. Authentication Architecture
FreeRADIUS operates as the Network Access Server (NAS) authenticator. When an employee or device connects to enterprise Wi-Fi or a secured switch port:
1. Outer EAP negotiates PEAP tunnel using the appliance TLS certificate.
2. Inner EAP negotiates MS-CHAPv2.
3. FreeRADIUS passes the MS-CHAP challenge and response parameters to Samba's `ntlm_auth` binary.
4. Winbind validates the credentials against Samba AD.
5. FreeRADIUS returns an `Access-Accept` with optional RFC 3580 Dynamic VLAN assignment.

### 3.2. MS-CHAP Module (`/etc/freeradius/3.0/mods-available/mschap`)
```ini
mschap {
    use_mppe = yes
    require_encryption = yes
    require_strong = yes

    # Helper binary pointing to Samba winbind privileged socket
    ntlm_auth = "/usr/bin/ntlm_auth --request-nt-key \
      --domain=CORP \
      --username=%{mschap:User-Name} \
      --challenge=%{%{mschap:Challenge}:-00} \
      --nt-response=%{%{mschap:NT-Response}:-00}"
}
```

### 3.3. Dynamic VLAN Steering by Active Directory Group (Standard Mode)
In `/etc/freeradius/3.0/mods-config/files/authorize` (or `/etc/freeradius/3.0/users`):
```text
# Domain Admins -> VLAN 1 (Infrastructure Management)
DEFAULT Group == "Domain Admins"
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = "1",
    Fall-Through = Yes

# Corporate Staff -> VLAN 50 (Corporate Data & Wi-Fi)
DEFAULT Group == "Corporate-Users"
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = "50",
    Fall-Through = Yes

# Contractors & Visitors -> VLAN 60 (Isolated Guest Access)
DEFAULT Group == "Contractors"
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = "60",
    Fall-Through = Yes
```

### 3.4. NAS Clients Definition (`/etc/freeradius/3.0/clients.conf`)
Managed dynamically via the ZclockID REST API with integrated cryptographically secure secret generator:
```text
client corporate_ap_cluster {
    ipaddr = 192.168.1.0/24
    secret = RadSecureSecret2026!
    shortname = corporate-wifi
    nas_type = cisco
}
```

### 3.5. MAC Authentication Bypass (MAB - Advanced Mode)
For headless devices (PoE IP cameras, network printers, VoIP desk phones) without 802.1X supplicants:
```text
# HP Color LaserJet MFP
"00:50:56:a1:b2:c3" Auth-Type := Accept
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = "70",
    Framed-IP-Address = 192.168.70.25,
    Fall-Through = Yes
```

### 3.6. Custom Vendor-Specific Attributes & Overrides (Advanced Mode)
Supports RFC and vendor-specific attributes (Cisco-AVPair, Session-Timeout, Idle-Timeout, Mikrotik-Rate-Limit) attached globally, per AD group, or per client:
```text
DEFAULT
    Session-Timeout = "28800",
    Fall-Through = Yes
```

### 3.7. Live Accounting Sessions & Raw Config Inspector
pfSense-style real-time accounting table tracks:
- Username, NAS IP / name, Calling-Station MAC, Framed IP, duration, octets in/out.
- One-click session termination (Disconnect / CoA).
- Built-in syntax-highlighted raw config inspector for `clients.conf`, `authorize`, `mschap`, and `eap.conf`.

---

## 4. Engine 4: Sysvol Synchronization & NTACL Self-Healing

### 4.1. The Extended Attributes Challenge
Samba stores Windows Access Control Lists (ACLs) in Linux extended attributes:
* `security.NTACL`: Contains the binary Windows Security Descriptor (Owner SID, Group SID, DACL, SACL).
* `user.SAMBA_PAI`: POSIX Access Inherited flags.

Standard multi-master file synchronization engines (such as default Syncthing or cloud storage syncs) only sync file payloads and POSIX permissions (`chmod 0755`). When files arrive on the secondary DC, the missing `security.NTACL` attribute causes Windows clients running Group Policy (`gpmc.msc`) to log:
`"Group Policy processing failed. Windows could not verify the user or computer accounts. Error 0x80070005 (Access is denied)."`

### 4.2. ZclockID Sysvol Synchronization Architecture
ZclockID solves this problem with a **two-tier architecture**:

```
[ Primary DC ]                                       [ Secondary DC ]
  RSAT GPMC writes GPO                                 
         │                                                    │
         ▼                                                    ▼
/var/lib/samba/sysvol/                               /var/lib/samba/sysvol/
         │                                                    │
         ▼ (inotify change)                                   ▲
zclock-sysvold (DC1) ───[ Rsync -XA / Syncthing ]───► zclock-sysvold (DC2)
                                                              │
                                                              ▼ (batch change event)
                                                      samba-tool ntacl sysvolreset
                                                              │
                                                              ▼
                                                      Flawless Windows GPO NTACLs!
```

1. **Replication Layer (`rsync -XA` or Syncthing):**
   * Transports file payload and directory hierarchies.
   * When using `rsync`, `-X` explicitly preserves extended attributes across the wire.
2. **Reconciliation Daemon (`zclock-sysvold`):**
   * A Python inotify daemon listening on `/var/lib/samba/sysvol/`.
   * Implements a **5-second debouncing window** (to allow multi-file GPO writes to finish).
   * Automatically executes `samba-tool ntacl sysvolreset` whenever GPOs are modified.
   * Verifies health using `samba-tool ntacl sysvolcheck`.

---

## 5. Engine 5: Net-SNMP & Telemetry Subsystem

### 5.1. Net-SNMP Integration (`/etc/snmp/snmpd.conf`)
ZclockID provides comprehensive SNMP v2c/v3 telemetry for monitoring systems:
```text
# Standard MIB-II Information
sysLocation    "Inet Secure Labs Datacenter"
sysContact     "sysadmin@inetcsc.com"
rocommunity    zclock_snmp 192.168.1.0/24

# Active Directory Custom Telemetry Pass-Through
extend .1.3.6.1.4.1.99999.1.1 ad_status        /usr/local/bin/zclock-telemetry.sh ad_status
extend .1.3.6.1.4.1.99999.1.2 drs_repl_health  /usr/local/bin/zclock-telemetry.sh drs_health
extend .1.3.6.1.4.1.99999.1.3 active_sessions  /usr/local/bin/zclock-telemetry.sh active_sessions
extend .1.3.6.1.4.1.99999.1.4 sysvol_health    /usr/local/bin/zclock-telemetry.sh sysvol_health
extend .1.3.6.1.4.1.99999.1.5 radius_auths     /usr/local/bin/zclock-telemetry.sh radius_auths
```

---

## 6. Engine 6: Keycloak SAML 2.0 & OIDC Identity Provider

### 6.1. Deployment Model
* **Runtime:** Keycloak 24+ containerized via Podman / Docker on localhost port `8080`, reverse-proxied via HTTPS `443` at `/auth`.
* **Database:** Embedded Quarkus / SQLite (lightweight appliances) or external MariaDB Galera cluster.

### 6.2. Active Directory LDAP User Federation
* **Provider ID:** `ldap`
* **Vendor:** `Active Directory`
* **Connection URL:** `ldaps://127.0.0.1:636`
* **Users DN:** `CN=Users,DC=corp,DC=example,DC=com`
* **Bind DN:** `CN=svc-keycloak,CN=Users,DC=corp,DC=example,DC=com`
* **Username Attribute:** `sAMAccountName`
* **RDN Attribute:** `cn`
* **UUID Attribute:** `objectGUID`
* **User Object Classes:** `person, organizationalPerson, user`

### 6.3. Kerberos SPNEGO Desktop SSO
* **Kerberos Realm:** `CORP.EXAMPLE.COM`
* **Server Principal:** `HTTP/idp.corp.example.com@CORP.EXAMPLE.COM`
* **Keytab File:** `/etc/keycloak/keycloak.keytab`
* **SPNEGO Authentication Flow:** Domain users logging into Windows experience zero-touch desktop SSO for web apps and cloud SaaS.

