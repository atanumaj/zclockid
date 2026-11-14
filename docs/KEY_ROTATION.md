# ZclockID Cryptographic Archive Key Rotation Runbook

## Overview
All ZclockID APT repository metadata (`InRelease`, `Release.gpg`) and standalone update archives (`.deb` packages paired with `.deb.sig` detached signatures) are cryptographically validated against the official archive keyring:
```
/usr/share/keyrings/zclockid-archive-keyring.gpg
```
APT sources and automated appliance updaters strictly prohibit insecure bypasses (insecure unverified repository flags are strictly forbidden across all configurations). Consequently, archive signing keys must be rotated seamlessly without disrupting active appliances or breaking APT automated updates.

---

## Key Rotation Architecture: Dual-Key Transition

To rotate the signing key without downtime:
1. **Never switch the active signing key abruptly.** Doing so will cause `APT` to fail with `EXPKEYSIG` or `NO_PUBKEY` errors across all installed systems.
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

## Step-by-Step Rotation Procedure

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
Name-Real: ZclockID Archive Automatic Signing Key (2026-2028)
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

## Emergency Key Revocation Runbook

If the private signing key is ever suspected of compromise:
1. Immediately generate a revocation certificate using `gpg --gen-revoke`.
2. Generate a replacement keypair (Key C) immediately.
3. Distribute an emergency hotfix package or out-of-band security patch that replaces `/usr/share/keyrings/zclockid-archive-keyring.gpg` with Key C.
4. Re-sign all repository metadata and packages using Key C.
