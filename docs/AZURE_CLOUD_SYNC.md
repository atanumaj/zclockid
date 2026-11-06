# ZclockID Microsoft Entra ID (Azure AD) Cloud Sync Specification

## 1. Executive Overview

A critical requirement for modern Active Directory Domain Controllers is **Hybrid Identity Synchronization** with Microsoft 365 and Microsoft Entra ID (Azure AD). When enterprise employees are created on-premises, their accounts, attributes, and passwords must synchronize with cloud services (Teams, Outlook, OneDrive, SharePoint, Azure).

ZclockID supports **two distinct synchronization architectures**:

1. **Native Direct Linux Sync (Embedded in ZclockID):**
   * Operates directly on the ZclockID appliance using Python and the Microsoft Graph REST API.
   * **Requires ZERO Windows Server VMs or Microsoft licenses.**
   * Ideal for SMEs, MSPs, and cost-conscious enterprise deployments.
2. **Microsoft Entra Connect via Windows Member Server (Official Microsoft Pathway):**
   * Uses Microsoft's official Windows MSI installer (`Microsoft Entra Connect` or `Entra Cloud Sync`) running on a Windows member server (such as `192.168.1.60`).
   * Connects to ZclockID over standard LDAP/LDAPS and RPC with DCSync rights.
   * Ideal for enterprise customers requiring Microsoft vendor support and warranty.

---

## 2. Architecture Comparison

```
Option 1: Native Direct Linux Sync (Zero Windows Server)
┌─────────────────────────────────┐                 ┌─────────────────────────────────┐
│        ZclockID Appliance       │                 │     Microsoft Cloud (M365)      │
│  ┌───────────┐   ┌────────────┐ │  OAuth2 / HTTPS │  ┌───────────────────────────┐  │
│  │ Samba AD  │──►│ zclock-    │─┼────────────────┼─►│ Microsoft Entra ID (Azure)│  │
│  │ (sam.ldb) │   │ azuresync  │ │   (Port 443)    │  │ • Users, Groups, PHS      │  │
│  └───────────┘   └────────────┘ │                 │  │ • Exchange Online / M365  │  │
└─────────────────────────────────┘                 └─────────────────────────────────┘

Option 2: Microsoft-Native Bridge (via Member Windows VM)
┌──────────────────┐         LDAP / RPC (389, 135)       ┌──────────────────────────┐         HTTPS 443         ┌─────────────────────┐
│    ZclockID      │◄────────────────────────────────────│   Windows Member Server  │──────────────────────────►│ Microsoft Entra ID │
│  (Samba AD DC)   │                                     │ (Microsoft Entra Connect)│                           │       (M365)        │
└──────────────────┘                                     └──────────────────────────┘                           └─────────────────────┘
```

| Dimension | Option 1: Native Direct Linux Sync | Option 2: Microsoft Entra Connect (Windows) |
| :--- | :--- | :--- |
| **Windows Server Required** | **NO (100% Linux Appliance)** | **YES (Requires Windows Server instance)** |
| **Microsoft OS Licensing** | **$0 (Zero CALs / Zero Windows licenses)** | ~$1,069 (Windows Server OS License) |
| **Synchronization Engine** | Python daemon (`zclock-azuresync`) + Microsoft Graph API | Official Microsoft Entra Connect MSI / Cloud Sync Agent |
| **Password Synchronization** | Supported via NT-hash export & Graph DirSync APIs | Supported via native Windows DCSync RPC |
| **Management Interface** | ZclockID Web Console & Headless REST API | Microsoft Entra Connect Wizard on Windows desktop |
| **Vendor Support** | Supported by ZclockID Appliance | Supported directly by Microsoft Support |
| **Writeback Features** | One-way on-prem to cloud (Samba $\rightarrow$ Azure) | Bi-directional (Password & Device Writeback) |

---

## 3. Option 1 Implementation: Native Direct Linux Sync (`zclock-azuresync`)

### 3.1. Prerequisites in Azure Portal
1. Register an App in **Microsoft Entra ID > App Registrations > New Registration**:
   * Name: `ZclockID-CloudSync`
   * Supported Account Types: Single Tenant
2. Grant **Application Permissions** (Microsoft Graph API):
   * `User.ReadWrite.All`
   * `Group.ReadWrite.All`
   * `Directory.ReadWrite.All`
   * `Domain.Read.All`
   * (Click *Grant admin consent for <Tenant>*).
3. Generate a **Client Secret** (copy Secret Value, Tenant ID, and Client ID).

### 3.2. Synchronization Flow
1. `zclock-azuresync` executes on a configurable interval (default: every 15 minutes or triggered via REST API).
2. It queries local Samba AD via `sam.ldb` or local LDAPS for accounts in the target OU (`OU=Users,DC=corp,DC=example,DC=com`):
   * `sAMAccountName`
   * `userPrincipalName` (`user@customer.com`)
   * `mail`
   * `givenName`, `sn`, `displayName`
   * `userAccountControl` (enabled / disabled)
3. Authenticates to `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token` using client credentials.
4. Queries Microsoft Graph `GET /v1.0/users?$filter=userPrincipalName eq '{upn}'`:
   * If user does not exist: calls `POST /v1.0/users` to provision with initial password.
   * If user exists: calls `PATCH /v1.0/users/{id}` to synchronize updated department, title, or disable state.
5. Logs sync telemetry and records result in ZclockID SQLite audit database.

---

## 4. Option 2 Implementation: Microsoft Entra Connect Compatibility

If your organization prefers using Microsoft's official Windows-based sync agent:

### 4.1. Joining Windows Server to ZclockID Domain
1. Deploy a small Windows Server VM (e.g. existing `192.168.1.60`).
2. Join it to the ZclockID Active Directory domain (`example.com`).
3. Log in with Domain Admin credentials (`aaatechno`).

### 4.2. Granting DCSync Permissions on Samba AD
Microsoft Entra Connect requires directory replication permissions to synchronize password hashes:
```bash
# On ZclockID Domain Controller:
# Ensure the Entra Sync service account has Replicating Directory Changes permissions
sudo samba-tool dsacl set --objectdn="DC=corp,DC=example,DC=com" \
  --sddl="(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;<SYNC_USER_SID>)"
```

### 4.3. Installing Microsoft Entra Connect
1. Download `AzureADConnect.msi` from Microsoft on the Windows Server.
2. Select **Custom Settings** > **Password Hash Synchronization (PHS)**.
3. Point to ZclockID as the on-premises Forest.
4. Entra Connect connects via standard LDAP/RPC and synchronizes all users seamlessly.

---

## 5. Conclusion & Recommendation

For **MVP 1**, ZclockID provides **both capabilities**:
1. **Built-in Native Azure Sync Module** for customers wanting a 100% turnkey Linux appliance with zero Microsoft license requirements.
2. **Full DCSync / AD Schema Compliance** for customers choosing to point Microsoft's official Windows Entra Connect agent at ZclockID.

