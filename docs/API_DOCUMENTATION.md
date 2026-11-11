# ZclockID Appliance REST API Documentation

**API Version:** `v1.3.0`  
**Protocol:** HTTPS  
**Base URL:** `https://<appliance-ip>/api/v1`  
**Interactive OpenAPI UI:** `https://<appliance-ip>/docs` (Swagger 3.1)  

---

## 1. Authentication & Security

All API endpoints (except `/api/v1/auth/login` and `/api/v1/status/health`) require authentication via either:

1. **Bearer JWT Token:**
   Include the token in the HTTP Authorization header:
   ```http
   Authorization: Bearer <access_token>
   ```
2. **API Key Header:**
   For headless automation, CI/CD pipelines, and monitoring platforms:
   ```http
   X-API-Key: <your_secret_api_key>
   ```

### 1.1. Login / Obtain Access Token
* **Endpoint:** `POST /api/v1/auth/login`
* **Request Body:**
  ```json
  {
    "username": "admin",
    "password": "YourPasswordHere"
  }
  ```
* **Response (200 OK):**
  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "username": "admin",
    "role": "SuperAdmin",
    "expires_in_hours": 8
  }
  ```

---

## 2. Appliance Health & System Telemetry

### 2.1. System Health Status
* **Endpoint:** `GET /api/v1/system/status`
* **Description:** Comprehensive real-time status of all core appliance daemons.
* **Response (200 OK):**
  ```json
  {
    "hostname": "dc01.corp.example.com",
    "appliance_version": "1.0.9",
    "uptime_seconds": 348200,
    "services": {
      "samba_ad_dc": { "status": "active", "substate": "running" },
      "bind9": { "status": "active", "substate": "running", "doh_enabled": true },
      "freeradius": { "status": "active", "substate": "running" },
      "chrony": { "status": "active", "substate": "running" },
      "sysvol_daemon": { "status": "active", "substate": "running" },
      "azure_sync": { "status": "active", "substate": "running" }
    },
    "overall_health": "HEALTHY"
  }
  ```

### 2.2. Hardware & Resource Metrics
* **Endpoint:** `GET /api/v1/system/resources`
* **Description:** Real-time CPU, RAM, disk, and network throughput telemetry.

### 2.3. Daemon Restart
* **Endpoint:** `POST /api/v1/system/service/{name}/restart`
* **Parameters:** `name` (`samba`, `bind9`, `freeradius`, `chrony`, `sysvol`, `azuresync`)

---

## 3. Active Directory & Domain Operations

### 3.1. Domain Information
* **Endpoint:** `GET /api/v1/domain/info`
* **Description:** Forest FQDN, NetBIOS name, domain SID, functional level, and schema version.

### 3.2. FSMO Roles
* **Endpoint:** `GET /api/v1/domain/fsmo`
* **Description:** Returns the current holder of all 5 FSMO roles (Schema Master, Domain Naming Master, RID Master, PDC Emulator, Infrastructure Master).
* **Transfer FSMO:** `POST /api/v1/domain/fsmo/transfer` (Transfers roles to the local DC).

### 3.3. DRS Replication Topology & Sync
* **Endpoint:** `GET /api/v1/domain/replication`
* **Description:** Live partner status, consecutive failures, and partition sync state.
* **Force Replication:** `POST /api/v1/domain/replication/sync`

---

## 4. Users & Security Groups

### 4.1. List Users
* **Endpoint:** `GET /api/v1/users`
* **Query Parameters:** `search`, `limit`, `offset`, `ou`

### 4.2. Provision Domain User
* **Endpoint:** `POST /api/v1/users`
* **Request Body:**
  ```json
  {
    "username": "rajesh.kumar",
    "first_name": "Rajesh",
    "last_name": "Kumar",
    "password": "InitialSecurePassword123!",
    "email": "rajesh.kumar@corp.example.com",
    "ou": "OU=Users,DC=corp,DC=example,DC=com",
    "department": "Engineering"
  }
  ```

### 4.3. User Operations
* `GET /api/v1/users/{username}`: Fetch user metadata and group memberships.
* `PATCH /api/v1/users/{username}`: Enable/disable account or modify attributes.
* `POST /api/v1/users/{username}/password`: Reset password.
* `POST /api/v1/users/{username}/unlock`: Clear account lockout state.

### 4.4. Security Groups
* `GET /api/v1/groups`: List domain security and distribution groups.
* `POST /api/v1/groups/{group}/members`: Add user to group.
* `DELETE /api/v1/groups/{group}/members/{username}`: Remove user from group.

---

## 5. Host Firewall & Port Protection

### 5.1. Firewall Status
* **Endpoint:** `GET /api/v1/security/firewall/status`
* **Description:** Stored database policies, unified rule list, rule counters, and live kernel UFW enforcement status.
* **Response (200 OK):**
  ```json
  {
    "is_enabled": true,
    "live_status": "active",
    "default_incoming": "DENY",
    "default_outgoing": "ALLOW",
    "total_rules_count": 21,
    "active_rules_count": 21,
    "rules": [
      {
        "id": 1,
        "action": "ALLOW",
        "protocol": "TCP",
        "port": "22",
        "source": "Any",
        "comment": "Administrative SSH Access",
        "is_enabled": true
      }
    ]
  }
  ```

### 5.2. Toggle Firewall Master Switch
* **Endpoint:** `POST /api/v1/security/firewall/toggle`
* **Request Body:**
  ```json
  {
    "is_enabled": true
  }
  ```

### 5.3. Add / Update Firewall Rules
* **Endpoint:** `POST /api/v1/security/firewall/rules`
* **Request Body:** (Supports comma-separated subnets in `source`)
  ```json
  {
    "action": "ALLOW",
    "protocol": "TCP",
    "port": "9090",
    "source": "192.168.1.0/24, 10.10.0.0/24, 180.92.168.34/32",
    "comment": "Prometheus Monitoring Multi-Subnet Ingress",
    "is_enabled": true
  }
  ```
* **Edit Rule:** `PUT /api/v1/security/firewall/rules/{id}`
* **Delete Rule:** `DELETE /api/v1/security/firewall/rules/{id}`
* **Toggle Rule:** `PATCH /api/v1/security/firewall/rules/{id}/toggle`
* **Revert Template:** `POST /api/v1/security/firewall/reset-template`
* **Force Sync:** `POST /api/v1/security/firewall/apply`

---

## 6. Access Control & System Hardening

### 6.1. Security Settings & OpenSSH Hardening
* **Endpoint:** `GET /api/v1/security/settings`
* **Description:** Retrieves detected client IP, session timeout thresholds, and OpenSSH daemon configuration.
* **Update Hardening:** `PUT /api/v1/security/settings`
  ```json
  {
    "session_idle_timeout_min": 15,
    "session_max_lifetime_hours": 8,
    "max_failed_logins": 5,
    "lockout_duration_min": 15,
    "ssh_permit_root": 0,
    "ssh_password_auth": 1
  }
  ```

### 6.2. Active Admin Sessions
* `GET /api/v1/security/sessions`: List active administrator web sessions.
* `DELETE /api/v1/security/sessions/{session_id}`: Terminate a specific session.
* `DELETE /api/v1/security/sessions/others`: Terminate all other sessions except caller.

---

## 7. DNS & Encrypted DNS-over-HTTPS (DoH)

* `GET /api/v1/dns/zones`: List integrated Active Directory DNS zones.
* `GET /api/v1/dns/zones/{zone}/records`: Query records in zone.
* `POST /api/v1/dns/zones/{zone}/records`: Add A, AAAA, CNAME, TXT, or SRV record.
* `DELETE /api/v1/dns/zones/{zone}/records/{name}`: Delete record.
* `GET /api/v1/dns/forwarders`: List upstream DNS forwarders.
* `PUT /api/v1/dns/forwarders`: Configure upstream DNS forwarders.

---

## 8. FreeRADIUS 802.1X & Captive Portal

* `GET /api/v1/radius/clients`: List authorized NAS switches and APs.
* `POST /api/v1/radius/clients`: Register a new NAS device.
* `DELETE /api/v1/radius/clients/{ip}`: Remove NAS device.
* `GET /api/v1/radius/bandwidth-profiles`: List configured bandwidth tiers.
* `POST /api/v1/radius/bandwidth-profiles`: Create bandwidth tier (e.g. `VIP-Executive 50M/25M`).
* `GET /api/v1/radius/stats`: Real-time authentication KPIs and radius accounting.

---

## 9. Sysvol Replication & Self-Healing

* `GET /api/v1/sysvol/status`: Current GPO file synchronization status and NTACL health.
* `POST /api/v1/sysvol/sync`: Trigger manual bi-directional Sysvol synchronization.
* `POST /api/v1/sysvol/reset-ntacl`: Run automated `samba-tool ntacl sysvolreset`.

---

## 10. Hybrid Cloud Synchronization (Microsoft Entra ID)

* `GET /api/v1/system/azure/status`: Current sync status, last run timestamp, and error telemetry.
* `POST /api/v1/system/azure/sync`: Trigger immediate synchronization with Microsoft Entra ID.
* `PUT /api/v1/system/azure/config`: Save Azure Tenant ID, Client ID, Client Secret, and Target OU.

---

## 11. 1-Click Update Center

### 11.1. Appliance Software Releases
* `GET /api/v1/system/update/info`: Get running version, channel lock, and release manifest details.
* `POST /api/v1/system/update/check`: Query official GitHub releases for updates.
* `POST /api/v1/system/update/install`: Download and install latest appliance package.
* `GET /api/v1/system/update/status`: Live progress and terminal installation logs.

### 11.2. Debian / Ubuntu OS Package Upgrades
* `GET /api/v1/system/update/os/check`: Scan for upgradable Ubuntu/Debian packages (kernel, openssl, systemd).
* `POST /api/v1/system/update/os/upgrade`: Trigger non-interactive package upgrade (`target: "all"` or `"security"`).
* `GET /api/v1/system/update/os/log`: Stream live APT upgrade terminal output.

---

## 12. Backup & Disaster Recovery

* `GET /api/v1/backup/list`: List existing AD and configuration backup archives.
* `POST /api/v1/backup/create`: Trigger online Active Directory snapshot (`samba-tool domain backup`).
* `GET /api/v1/backup/download/{filename}`: Download backup tarball.

---

## 13. Self Services, SSPR, SMS Testing & Custom Portal Templates

### 13.1. Self-Registration Portal & Admin Queue
* `GET /api/v1/public/register/config`: Public onboarding configuration, primary realm, and department list.
* `POST /api/v1/public/register/initiate`: Submit signup request and dispatch mobile OTP if required.
* `POST /api/v1/public/register/verify-otp`: Verify 6-digit OTP and auto-provision user into Active Directory.
* `POST /api/v1/public/register/resend-otp`: Re-dispatch registration OTP.
* `GET /api/v1/registrations/requests`: List signup queue (`status_filter`).
* `GET /api/v1/registrations/settings` & `POST /api/v1/registrations/settings`: Read/update registration, provisioning, SMTP, and SMS gateway settings.
* `GET /api/v1/self-service/registrations/export`: Download filtered registration records as CSV (`status_filter`, `month`, `search`).

### 13.2. Self-Service Password Reset (SSPR)
* `GET /api/v1/self-service/password/config`: Public SSPR policy, enabled methods, password rules, and primary realm.
* `POST /api/v1/self-service/password/change-with-old`: Direct password change authenticating user's current password over localhost Samba SAMR.
* `POST /api/v1/self-service/password/request-otp`: Look up AD user `mail` / `mobile` attributes and dispatch verification OTP (`channel`: `"email"` or `"sms"`). Returns HTTP `400` prompting Domain Administrator contact if contact attribute is absent.
* `POST /api/v1/self-service/password/verify-and-reset`: Validate OTP and reset password in Active Directory.
* `GET /api/v1/self-service/password/settings` & `POST /api/v1/self-service/password/settings`: Read/update SSPR policies, OTP/password rules, SMTP, and SMS settings.
* `GET /api/v1/self-service/password/logs`: Query password reset logs (`month`, `status_filter`, `search`, `limit`).
* `GET /api/v1/self-service/password/logs/export`: Download filtered SSPR audit trail as CSV (`method`, `status`, `month`, `search`).

### 13.3. SMS Gateway Testing
* `POST /api/v1/self-service/test-sms`: Dispatch a one-off test SMS (`123456`) using unsaved or saved gateway parameters (`mobile`, `sms_gateway_type`, `sms_gateway_url`, `sms_api_key`, `sms_sender_id`, `sms_template`). Supports `webhook` HTTP `GET` query templates (`{to}`, `{to10}`, `{message}`, `{sender}`, `{apikey}`) and `POST` JSON payloads.

### 13.4. Custom Portal HTML Templates & Branding Assets (pfSense-Style)
*(Routes for `{portal_type}` accept `registration` or `password`)*
* `GET /api/v1/self-service/portal-template/{portal_type}/status`: Get custom HTML activation state, file metadata, and uploaded assets list.
* `GET /api/v1/self-service/portal-template/{portal_type}/example`: Download commented starter HTML template (`zclockid-register-example.html` or `zclockid-password-reset-example.html`).
* `POST /api/v1/self-service/portal-template/{portal_type}/upload`: Multipart upload of custom `.html`/`.htm` template (saved to `DATA_DIR/portals/` and activated).
* `POST /api/v1/self-service/portal-template/{portal_type}/toggle`: Enable/disable custom HTML override (`{"use_custom_html": true|false}`).
* `DELETE /api/v1/self-service/portal-template/{portal_type}`: Delete custom HTML file and revert to built-in portal template.
* `GET /api/v1/self-service/portal-assets`: List uploaded branding assets.
* `POST /api/v1/self-service/portal-assets/upload`: Upload logo/image/CSS asset (`.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.webp`, `.ico`, `.css`, max 5 MB) served publicly at `GET /portal-assets/{filename}`.
* `DELETE /api/v1/self-service/portal-assets/{filename}`: Delete an uploaded portal asset.

