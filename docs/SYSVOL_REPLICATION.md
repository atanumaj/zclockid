# ZclockID Sysvol Replication Architecture & Operations Guide

## Overview

In Active Directory Domain Services, the **SYSVOL** share hosts Group Policy Objects (GPOs), policy templates (`gpt.ini`), and logon/logoff scripts. Samba AD DC replicates LDAP directory partitions natively via Directory Replication Service (DRS), but **does not natively replicate the POSIX/NTACL SYSVOL filesystem**.

ZclockID includes an integrated, high-performance bi-directional SYSVOL replication daemon (**`zclock-sysvold`**, written in Go with an equivalent Python fallback) and secure REST API (`/api/v1/sysvol/*`). It maintains cryptographic data integrity across paired Domain Controllers while continuously guarding Windows NT Security Descriptors (NTACLs).

---

## 1. Replication Architecture

```
+-------------------------------------------------------------------+
|               Primary Domain Controller (e.g. DC1)                |
|                                                                   |
|   +-----------------------+              +--------------------+   |
|   | Samba AD DC (SYSVOL)  |<------------>|   zclock-sysvold   |   |
|   | /var/lib/samba/sysvol | (in-kernel   | (Go Sync Engine &  |   |
|   +-----------------------+  inotify)    |  NTACL Guardian)   |   |
|                                          +---------+----------+   |
|                                                    |              |
+----------------------------------------------------|--------------+
                                                     | HTTPS :443
                                                     | Mutual Secret &
                                                     | Pinned TLS SHA-256
                                                     v
+----------------------------------------------------+--------------+
|                                                    |              |
|                                          +---------+----------+   |
|   +-----------------------+              |   zclock-sysvold   |   |
|   | Samba AD DC (SYSVOL)  |<------------>| (Go Sync Engine &  |   |
|   | /var/lib/samba/sysvol | (in-kernel   |  NTACL Guardian)   |   |
|   +-----------------------+  inotify)    +--------------------+   |
|                                                                   |
|              Secondary Domain Controller (e.g. DC2)               |
+-------------------------------------------------------------------+
```

### Key Components

- **Sync Engine (`zclock-sysvold`)**: Continuously monitors the local SYSVOL directory tree using in-kernel `inotify`. Every 15 seconds (or immediately following filesystem events after a debouncing period), it synchronizes with all registered partner DCs.
- **REST Endpoints (`/api/v1/sysvol/*`)**:
  - `GET /api/v1/sysvol/manifest`: Returns SHA-256 hash tree, mtimes, sizes, and active tombstones.
  - `GET /api/v1/sysvol/file`: Streams file content with content-length validation.
  - `POST /api/v1/sysvol/file`: Peer-authenticated upload with mandatory SHA-256 integrity verification.
  - `POST /api/v1/sysvol/partners/{ip}/repin`: Admin-driven TLS certificate re-pinning.
  - `POST /api/v1/sysvol/mass-delete/confirm`: Manual release for the mass-deletion safety brake.
- **Debounced NTACL Guardian**: Standard Linux synchronization utilities corrupt Windows NT security descriptors. Whenever changes arrive from a peer DC, `zclock-sysvold` waits 4 seconds for transfers to settle, then executes `samba-tool ntacl sysvolreset` to guarantee that Windows clients never receive `Access Denied (Event ID 1058)` errors.

---

## 2. Synchronization & "Newest-Wins" Conflict Resolution

File reconciliation follows deterministic rules:
1. **Manifest Comparison**: The daemon downloads the partner's manifest and compares it against local files and tombstones.
2. **Hash & mtime Evaluation**:
   - If SHA-256 hashes match: the file is in sync.
   - If hashes differ: the file with the **newer modification time (`mtime`)** wins.
3. **Download & Atomic Staging**:
   - The file is downloaded to a temporary file (`.tmp`).
   - The download size is strictly capped at **50 MB** on both client and server to prevent resource exhaustion attacks.
   - The client calculates the SHA-256 hash of the downloaded `.tmp` file and compares it to the remote manifest hash. On mismatch, the `.tmp` file is immediately unlinked and deleted without touching the target.
   - Once verified, the file is atomically renamed into place (`os.replace` / `os.Rename`) and remote `mtime` is preserved (`os.utime` / `os.Chtimes`).

---

## 3. PDC Emulator Operational Requirement

In an Active Directory domain, the **PDC Emulator** FSMO role holder is the authoritative target for Group Policy management:

> [!IMPORTANT]
> When modifying GPOs via Microsoft Remote Server Administration Tools (RSAT) or the Group Policy Management Console (`gpmc.msc`), **always connect GPMC to the PDC Emulator**.

### Why?
- RSAT GPMC connects by default to the PDC Emulator.
- If an administrator edits a policy on DC2 while another admin edits on DC1, the **newer mtime wins**, which could overwrite intermediate changes.
- Making policy edits on the PDC Emulator guarantees a clean, unidirectional propagation flow from Primary DC to Backup DCs.

To inspect which DC currently holds the PDC Emulator role:
```bash
samba-tool fsmo show
```

---

## 4. Tombstones & Deletion Propagation

In peer-to-peer replication without tombstones, deleting a file on DC1 would cause it to be pulled back from DC2 on the subsequent sync cycle. ZclockID implements **state-tracked tombstones**:

### State Tracking (`sysvol_state.json`)
The daemon maintains `/var/lib/zclockid/sysvol_state.json` (mode `0600`, owned `root:root`). It records:
- The snapshot of files present after the last successful scan.
- An array of tombstones:
  ```json
  {
    "rel_path": "Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/gpt.ini",
    "deleted_at": 1700000000.0,
    "hash_at_delete": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
  ```

### Deletion Rules
- **Pull-Based Deletion**: Deletions are applied on pull. When DC2 syncs from DC1, it reads DC1's tombstones.
- **Integrity Check (`hash_at_delete`)**: If DC2 has the file and its local SHA-256 matches `hash_at_delete`, DC2 deletes its local copy.
- **Modified Beats Deleted**: If DC2 modified the file after `deleted_at` or its hash differs from `hash_at_delete`, DC2 **keeps its file** and logs a conflict warning.
- **No Resurrection**: A DC never pulls a file listed in its own tombstones unless the remote copy is strictly newer than `deleted_at` and has a different hash.
- **Directory Pruning**: When a file is deleted, empty parent directories are pruned up the tree, strictly preserving:
  - SYSVOL root
  - `<domain>` root
  - `<domain>/Policies`
  - `<domain>/scripts`
- **Tombstone Expiration**: Tombstones are automatically purged after **30 days**.

---

## 5. Mass-Deletion Safety Brake

To prevent catastrophic accidental or malicious wiping of GPO directories, ZclockID enforces an automated safety brake:

> [!WARNING]
> If a single synchronization cycle would delete **more than 20% of all files** or **more than 50 files**, the engine aborts deletions immediately.

When the brake trips:
1. No files are deleted.
2. The replication health status transitions to `ERROR`.
3. The Web Console displays a persistent alert banner:
   *"Safety Brake Tripped: High-Volume Sysvol Deletions Suspended"*.
4. Replication remains suspended for deletions until an operator or administrator confirms the action.

### Releasing the Brake
- **Via Web Console**: Navigate to **SYSVOL** tab and click **Confirm Deletions & Resume**.
- **Via REST API** (Requires `operator` or `fulladmin` role):
  ```bash
  curl -X POST https://<dc-ip>/api/v1/sysvol/mass-delete/confirm \
    -H "Authorization: Bearer <token>"
  ```

---

## 6. Mutual Authentication & Certificate Pinning

Replication traffic between Domain Controllers is protected by two layers of security:

### 1. Peer IP & Mutual Secret Binding
- Inbound requests to `/api/v1/sysvol/*` must present the `X-Zclock-Sync-Secret` header.
- The secret is strictly bound to the remote peer's IP (`request.client.host` via trusted reverse proxy). Partner A's secret sent from Partner B's IP is rejected with `401 Unauthorized`.
- Secrets are stored in `/etc/zclockid/sysvol_partners.json` with permissions **`0600`** (root-only access) and masked (`****xxxx`) in all API responses.

### 2. TLS Certificate SHA-256 Pinning
- Insecure certificate validation (`InsecureSkipVerify` / `CERT_NONE`) is strictly prohibited.
- When pairing a partner DC, its TLS certificate is probed and its SHA-256 fingerprint is calculated and stored.
- On every sync attempt, the daemon verifies the peer's certificate against the pinned fingerprint.
- If the peer's certificate changes without being re-pinned, the daemon marks the partner as `ERROR ("certificate changed: re-pin required")` and halts sync with that peer.

### Re-pinning After Certificate Renewal
When an appliance's self-signed or CA certificate is renewed, the fingerprint must be re-pinned:
1. Verify the local fingerprint on the target DC from its Web Console header or via CLI:
   ```bash
   openssl x509 -noout -fingerprint -sha256 -in /etc/zclockid/certs/appliance.crt
   ```
2. On the partner DC Web Console, navigate to **SYSVOL** $\rightarrow$ Click **Re-pin** next to the partner DC $\rightarrow$ Confirm the probed fingerprint matches.
3. Or via API (`fulladmin` required):
   ```bash
   curl -X POST https://<dc-ip>/api/v1/sysvol/partners/<partner-ip>/repin \
     -H "Authorization: Bearer <fulladmin-token>" \
     -H "Content-Type: application/json" \
     -d '{"confirm": true}'
   ```
   Every re-pin event generates an immutable audit log entry: `SYSVOL_PARTNER_REPINNED`.
