# ZclockID Cryptographic Archive Key Rotation & Secret Hygiene Runbook

## 1. Active Release Signing Key Specification

The current active production signing key for ZclockID APT packages and repository metadata has the following specification:

* **Primary Key ID:** `F85A53762E2BADA8C5FF6AF4408D10F3F78600EE`
* **Signing Subkey ID:** `3297D3B1C68C86019417F0EF4F442C36A3937429`
* **Real Name:** `ZclockID Archive Automatic Signing Key (2026-2028)`
* **Email:** `security@zclockid.local`
* **Algorithm:** RSA 4096-bit (Sign Only)
* **Expiry:** 2028-11-13 (2-Year Expiration Window)
* **Official Keyring Path:** `/usr/share/keyrings/zclockid-archive-keyring.gpg`
* **Keyring Source Path:** `package/keyrings/zclockid-archive-keyring.gpg`

### Key Fingerprint Reference
```text
pub   rsa4096 2026-11-13 [SC] [expires: 2028-11-13]
      F85A 5376 2E2B ADA8 C5FF  6AF4 408D 10F3 F786 00EE
uid           ZclockID Archive Automatic Signing Key (2026-2028) <security@zclockid.local>
sub   rsa4096 2026-11-13 [S] [expires: 2028-11-13]
      3297 D3B1 C68C 8601 9417  F0EF 4F44 2C36 A393 7429
```

---

## 2. Signing Key Hygiene & Secret Protection Architecture

In accordance with enterprise secret management standards:
1. **Passphrase Protection**: The private secret key is encrypted with an AES-256 passphrase.
2. **macOS Keychain Integration**:
   The passphrase is stored securely in the local macOS Keychain:
   ```bash
   # Retrieve signing passphrase programmatically from Keychain:
   KEY_PASS=$(security find-generic-password -s "zclockid-signing-key" -a "security@zclockid.local" -w)
   ```
   A secured local backup of the passphrase is also kept with strict POSIX permissions:
   `~/.zclockid-signing-key/passphrase` (`chmod 0600`).
3. **Loopback Pinentry for Non-Interactive Automation**:
   The local GnuPG agent is configured with `allow-loopback-pinentry` in `~/.zclockid-signing-key/gpg-agent.conf`, enabling automated remote build and packaging scripts to pass the passphrase cleanly without prompting or stalling.
4. **Offline Disaster Recovery Storage**:
   Offline disaster recovery exports are archived under `~/.zclockid-signing-key/offline-backup/` (`chmod 0700`, files `chmod 0600`):
   * `revocation.asc`: Pre-generated cryptographic revocation certificate ready for emergency broadcast.
   * `secret-key-encrypted-backup.asc`: Encrypted private key backup.
   * `public-key.asc`: ASCII-armored public key.
5. **Private Update Staging**:
   Downloaded or uploaded packages and detached `.sig` files are strictly staged in `/var/lib/zclockid/updates/` (`chmod 0700`, owned `root:root`). Signature verification fails closed: if the detached `.sig` or archive keyring is missing or invalid, installation is aborted immediately.

---

## 3. Key Rotation Architecture: Dual-Key Transition

To rotate the signing key without downtime:
1. **Never switch the active signing key abruptly.** Doing so causes `APT` to fail with `EXPKEYSIG` or `NO_PUBKEY` errors across all installed systems.
2. **Dual-Key Keyring Window**: An archive keyring can hold multiple trusted public keys simultaneously. By shipping an updated keyring containing **both** the current (Key A) and the upcoming (Key B) public keys, existing systems can verify artifacts signed by either key.
3. **Cutover**: Once the updated keyring is deployed across appliances, upstream repository metadata and package signatures are switched to Key B.
4. **Retirement**: In a subsequent release cycle, Key A is removed from the keyring once all instances are upgraded.

```
Phase 1: Keyring holds [Key A]          -> Signs repo with Key A
Phase 2: Keyring holds [Key A + Key B]  -> Ships via v1.x update (still signed with Key A)
Phase 3: Keyring holds [Key A + Key B]  -> Repository signing cutover to Key B
Phase 4: Keyring holds [Key B]          -> Key A retired in subsequent release
```

---

## 4. Step-by-Step Rotation Procedure

### Step 1: Generate the New GPG Signing Keypair
Generate a dedicated RSA 4096-bit key on an offline, air-gapped security workstation:

```bash
mkdir -p ~/.zclockid-signing-key-v2
chmod 700 ~/.zclockid-signing-key-v2

cat << 'EOF' > ~/.zclockid-signing-key-v2/keygen.batch
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: sign
Name-Real: ZclockID Archive Automatic Signing Key (2028-2030)
Name-Email: security@zclockid.local
Expire-Date: 2y
%commit
EOF

gpg --homedir ~/.zclockid-signing-key-v2 --batch --generate-key ~/.zclockid-signing-key-v2/keygen.batch
```

Identify the new Key ID and Fingerprint:
```bash
gpg --homedir ~/.zclockid-signing-key-v2 --list-secret-keys --keyid-format LONG
```

### Step 2: Construct the Dual-Key Keyring
Export the new public key and merge it with the existing trusted keyring:

```bash
# 1. Export the existing keyring into a working directory
gpg --no-default-keyring --keyring ./temp-keyring.gpg --import package/keyrings/zclockid-archive-keyring.gpg

# 2. Export the new public key from the new key home
gpg --homedir ~/.zclockid-signing-key-v2 --armor --export security@zclockid.local > /tmp/zclockid-new.asc

# 3. Import the new public key into the temporary keyring
gpg --no-default-keyring --keyring ./temp-keyring.gpg --import /tmp/zclockid-new.asc

# 4. Replace the repository keyring with the merged dual-key binary keyring
cp ./temp-keyring.gpg package/keyrings/zclockid-archive-keyring.gpg
chmod 0644 package/keyrings/zclockid-archive-keyring.gpg

# Also export ASCII armored combined key for documentation / manual installation:
gpg --no-default-keyring --keyring package/keyrings/zclockid-archive-keyring.gpg --armor --export > package/keyrings/zclockid-archive-keyring.asc
```

Verify that both keys are present in the keyring:
```bash
gpgv --keyring package/keyrings/zclockid-archive-keyring.gpg --list-keys
```

### Step 3: Ship the Dual Keyring in an Appliance Release
1. Build and release an intermediate version of ZclockID (e.g., `v1.4.x`).
2. The package `.deb` installs `/usr/share/keyrings/zclockid-archive-keyring.gpg` with both Key A and Key B.
3. Sign this release using **Key A** (the existing key that all currently deployed appliances still trust).
4. Deploy the release across production appliances and verify the keyring file on target hosts:
   ```bash
   gpgv --keyring /usr/share/keyrings/zclockid-archive-keyring.gpg --list-keys
   ```

### Step 4: Cut Over Repository Signing to Key B
Once the dual keyring is installed across appliances:
1. Switch repository metadata signing in `apt-repo/dists/stable/` to Key B:
   ```bash
   cd apt-repo/dists/stable
   rm -f InRelease Release.gpg

   # Clear-sign InRelease with Key B
   gpg --homedir ~/.zclockid-signing-key-v2 --batch --yes --clearsign -o InRelease Release

   # Detached signature Release.gpg with Key B
   gpg --homedir ~/.zclockid-signing-key-v2 --batch --yes -b -a -o Release.gpg Release
   ```
2. For all new `.deb` packages released after this point, sign with Key B:
   ```bash
   gpg --homedir ~/.zclockid-signing-key-v2 --batch --yes --detach-sign -o zclockid_1.5.0_all.deb.sig zclockid_1.5.0_all.deb
   ```
3. Appliances with the dual keyring will verify Key B signatures cleanly.

### Step 5: Retire the Old Key (Key A)
After the transition window (typically 30–60 days):
1. Create a clean keyring containing only Key B:
   ```bash
   gpg --homedir ~/.zclockid-signing-key-v2 --export > package/keyrings/zclockid-archive-keyring.gpg
   ```
2. Ship this single-key keyring in the next version update.

---

## 5. Emergency Key Revocation Runbook

If the private signing key is ever suspected of compromise:
1. Deploy the pre-generated revocation certificate from offline storage:
   `~/.zclockid-signing-key/offline-backup/revocation.asc`.
2. Generate a replacement keypair (Key C) immediately and save new revocation and offline backups.
3. Distribute an emergency hotfix package or out-of-band security patch that replaces `/usr/share/keyrings/zclockid-archive-keyring.gpg` with Key C.
4. Re-sign all repository metadata and packages using Key C.
Export the new public key and merge it with the existing trusted keyring:

```bash
# 1. Export the existing keyring into a working directory
gpg --no-default-keyring --keyring ./temp-keyring.gpg --import package/keyrings/zclockid-archive-keyring.gpg

# 2. Export the new public key from the new key home
gpg --homedir ~/.zclockid-signing-key-v2 --armor --export security@zclockid.local > /tmp/zclockid-new.asc

# 3. Import the new public key into the temporary keyring
gpg --no-default-keyring --keyring ./temp-keyring.gpg --import /tmp/zclockid-new.asc

# 4. Replace the repository keyring with the merged dual-key binary keyring
cp ./temp-keyring.gpg package/keyrings/zclockid-archive-keyring.gpg
chmod 0644 package/keyrings/zclockid-archive-keyring.gpg

# Also export ASCII armored combined key for documentation / manual installation:
gpg --no-default-keyring --keyring package/keyrings/zclockid-archive-keyring.gpg --armor --export > package/keyrings/zclockid-archive-keyring.asc
```

Verify that both keys are present in the keyring:
```bash
gpgv --keyring package/keyrings/zclockid-archive-keyring.gpg --list-keys
```

### Step 3: Ship the Dual Keyring in an Appliance Release
1. Build and release an intermediate version of ZclockID (e.g., `v1.4.x`).
2. The package `.deb` installs `/usr/share/keyrings/zclockid-archive-keyring.gpg` with both Key A and Key B.
3. Sign this release using **Key A** (the existing key that all currently deployed appliances still trust).
4. Deploy the release across production appliances and verify the keyring file on target hosts:
   ```bash
   gpgv --keyring /usr/share/keyrings/zclockid-archive-keyring.gpg --list-keys
   ```

### Step 4: Cut Over Repository Signing to Key B
Once the dual keyring is installed across appliances:
1. Switch repository metadata signing in `apt-repo/dists/stable/` to Key B:
   ```bash
   cd apt-repo/dists/stable
   rm -f InRelease Release.gpg

   # Clear-sign InRelease with Key B
   gpg --homedir ~/.zclockid-signing-key-v2 --batch --yes --clearsign -o InRelease Release

   # Detached signature Release.gpg with Key B
   gpg --homedir ~/.zclockid-signing-key-v2 --batch --yes -b -a -o Release.gpg Release
   ```
2. For all new `.deb` packages released after this point, sign with Key B:
   ```bash
   gpg --homedir ~/.zclockid-signing-key-v2 --batch --yes --detach-sign -o zclockid_1.5.0_all.deb.sig zclockid_1.5.0_all.deb
   ```
3. Appliances with the dual keyring will verify Key B signatures cleanly.

### Step 5: Retire the Old Key (Key A)
After the transition window (typically 30–60 days):
1. Create a clean keyring containing only Key B:
   ```bash
   gpg --homedir ~/.zclockid-signing-key-v2 --export > package/keyrings/zclockid-archive-keyring.gpg
   ```
2. Ship this single-key keyring in the next version update.

---

## Emergency Key Revocation Runbook

If the private signing key is ever suspected of compromise:
1. Immediately generate a revocation certificate using `gpg --gen-revoke`.
2. Generate a replacement keypair (Key C) immediately.
3. Distribute an emergency hotfix package or out-of-band security patch that replaces `/usr/share/keyrings/zclockid-archive-keyring.gpg` with Key C.
4. Re-sign all repository metadata and packages using Key C.
