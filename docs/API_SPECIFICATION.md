# ZclockID Headless REST API Specification

**API Version:** `v1.0.0`  
**Protocol:** HTTPS  
**Base URL:** `https://<appliance-ip>/api/v1`  
**Documentation:** Interactive Swagger UI at `https://<appliance-ip>/docs` (OpenAPI 3.1)  

---

## 1. Authentication & Security

All API endpoints (except `/api/v1/auth/login` and `/api/v1/status/health`) require authentication via either:
1. **Bearer JWT Token:** Generated via `/api/v1/auth/login` using appliance admin credentials.
2. **API Key Header:** `X-API-Key: <secret_key>` for automated CI/CD and MSP monitoring integrations.

---

## 2. API Endpoint Matrix

### 2.1. Authentication (`/api/v1/auth`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Authenticate admin user, returns JWT access token |
| `POST` | `/api/v1/auth/refresh` | Refresh an existing JWT access token |
| `GET` | `/api/v1/auth/me` | Return currently authenticated administrator profile |

---

### 2.2. Appliance Health & System Telemetry (`/api/v1/system`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/system/status` | Comprehensive status of all core engines (Samba, BIND9, FreeRADIUS, Sysvol, Keycloak) |
| `GET` | `/api/v1/system/resources` | CPU, RAM, Datastore, and Network bandwidth utilization |
| `POST` | `/api/v1/system/service/{name}/restart` | Safely restart a specific subsystem daemon |
| `POST` | `/api/v1/system/reboot` | Initiate graceful appliance reboot |

#### Response Example: `GET /api/v1/system/status`
```json
{
  "hostname": "dc1.corp.example.com",
  "appliance_version": "1.0.0-LTS",
  "uptime_seconds": 864200,
  "services": {
    "samba_ad_dc": { "status": "active", "substate": "running", "pid": 1284 },
    "bind9": { "status": "active", "substate": "running", "doh_enabled": true },
    "freeradius": { "status": "active", "substate": "running", "active_clients": 12 },
    "sysvol_daemon": { "status": "active", "substate": "running", "last_sync_age_sec": 42 },
    "keycloak": { "status": "active", "substate": "running", "sso_federated": true }
  },
  "overall_health": "HEALTHY"
}
```

---

### 2.3. Active Directory Domain Operations (`/api/v1/domain`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/domain/info` | Forest name, domain NetBIOS name, domain SID, schema version |
| `GET` | `/api/v1/domain/fsmo` | Current holders of all 5 FSMO roles |
| `POST` | `/api/v1/domain/fsmo/transfer` | Gracefully transfer one or all FSMO roles to local DC |
| `GET` | `/api/v1/domain/replication` | Live DRS replication topology and partner health matrix |
| `POST` | `/api/v1/domain/replication/sync` | Force immediate DRS directory partition replication |

#### Response Example: `GET /api/v1/domain/replication`
```json
{
  "local_dc": "CN=DC1,OU=Domain Controllers,DC=corp,DC=example,DC=com",
  "replication_partners": [
    {
      "partner_dc": "DC2.corp.example.com",
      "partitions": [
        { "name": "DC=corp,DC=example,DC=com", "status": "SUCCESS", "last_attempt": "2026-11-02T22:30:00Z", "consecutive_failures": 0 },
        { "name": "CN=Configuration,DC=corp,DC=example,DC=com", "status": "SUCCESS", "last_attempt": "2026-11-02T22:30:01Z", "consecutive_failures": 0 },
        { "name": "CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com", "status": "SUCCESS", "last_attempt": "2026-11-02T22:30:02Z", "consecutive_failures": 0 }
      ]
    }
  ],
  "replication_health": "OPTIMAL"
}
```

---

### 2.4. User & Group Lifecycle (`/api/v1/users` & `/api/v1/groups`)

*(Designed for API automation and simple web management while heavy-duty administration is handled via RSAT)*

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/users` | List domain user accounts with filtering & pagination |
| `POST` | `/api/v1/users` | Provision a new domain user account |
| `GET` | `/api/v1/users/{username}` | Get user metadata, OU, email, status, and group memberships |
| `PATCH` | `/api/v1/users/{username}` | Enable/disable user, set expiry, or update profile |
| `POST` | `/api/v1/users/{username}/password` | Reset user password (with optional 'must change at next logon') |
| `POST` | `/api/v1/users/{username}/unlock` | Clear lockout state for locked-out user |
| `GET` | `/api/v1/groups` | List domain security and distribution groups |
| `POST` | `/api/v1/groups/{group}/members` | Add user to security group |
| `DELETE` | `/api/v1/groups/{group}/members/{username}` | Remove user from security group |

---

### 2.5. DNS & DNS-over-HTTPS (`/api/v1/dns`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/dns/zones` | List all Active Directory integrated DNS zones |
| `GET` | `/api/v1/dns/zones/{zone}/records` | Query DNS records in zone |
| `POST` | `/api/v1/dns/zones/{zone}/records` | Add new A, AAAA, CNAME, TXT, or SRV record |
| `DELETE` | `/api/v1/dns/zones/{zone}/records/{name}` | Delete DNS record |
| `GET` | `/api/v1/dns/doh/status` | Real-time telemetry on DNS-over-HTTPS connections and queries |

---

### 2.6. FreeRADIUS 802.1X Access Control (`/api/v1/radius`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/radius/clients` | List configured Network Access Servers (Switches / APs) |
| `POST` | `/api/v1/radius/clients` | Register a new NAS switch or AP with shared secret |
| `DELETE` | `/api/v1/radius/clients/{ip}` | Remove an authorized NAS device |
| `GET` | `/api/v1/radius/stats` | Real-time auth metrics (Access-Accept, Access-Reject, timeouts) |
| `POST` | `/api/v1/radius/test-auth` | Test credentials against FreeRADIUS + Samba AD pipeline |

---

### 2.7. Sysvol Synchronization & NTACL Maintenance (`/api/v1/sysvol`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/sysvol/status` | Current file sync state, peer connections, and NTACL audit |
| `POST` | `/api/v1/sysvol/sync` | Force immediate file synchronization with peer DCs |
| `POST` | `/api/v1/sysvol/reset-ntacl` | Execute `samba-tool ntacl sysvolreset` to restore Windows ACLs |
| `GET` | `/api/v1/sysvol/gpo-list` | List detected Group Policy Objects and their GUIDs |

---

### 2.8. User Self-Registration Subsystem (`/api/v1/registration`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/registration/submit` | Public endpoint: Submit user self-registration request |
| `GET` | `/api/v1/registration/pending` | Admin endpoint: List all pending registrations awaiting approval |
| `GET` | `/api/v1/registration/all` | Admin endpoint: List all registration requests with status |
| `POST` | `/api/v1/registration/{id}/approve` | Admin endpoint: Approve request and provision user into Samba AD |
| `POST` | `/api/v1/registration/{id}/reject` | Admin endpoint: Reject request with reason and record in audit log |

---

### 2.9. Detail Reporting & Audit Subsystem (`/api/v1/reports`)

*(Zero billing overhead — strictly focused on compliance, registration metrics, and directory audit trails)*

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/reports/summary` | High-level summary of registrations, user states, and audit counts |
| `GET` | `/api/v1/reports/audit-events` | Query audit trail with event filtering (`event_type`) and pagination |
| `GET` | `/api/v1/reports/export/csv` | Export detailed reports in CSV format (`?report_type=registrations` or `audit`) |

---

### 2.10. Disaster Recovery & Backups (`/api/v1/backup`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/backup/list` | List existing local and remote AD backup archives |
| `POST` | `/api/v1/backup/create` | Trigger full online Samba AD backup (`samba-tool domain backup`) |
| `POST` | `/api/v1/backup/download/{id}` | Export encrypted backup archive for offsite storage |

