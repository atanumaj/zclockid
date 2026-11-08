# ZclockID Master License Generator (Vendor Tool)

This folder contains the vendor-side cryptographic tool to generate and issue official `zclockid.lic` license certificates for ZclockID Enterprise appliances.

> [!CAUTION]
> **Keep your private key (`zclockid_private_key.pem`) secret!**
> Host this tool inside your private Git repository or an offline administration vault. Never commit the private key to public repositories or bundle it with appliance packages.

---

## 1. Master Keypair

* **`zclockid_private_key.pem`**: Vendor master Ed25519 private key (Used strictly to sign licenses).
* **`zclockid_public_key.pem`**: Public verification key (Embedded into ZclockID appliances to verify authenticity).

To generate a new keypair (if ever needed):
```bash
python3 keygen.py
```

---

## 2. Generating a License (`zclockid.lic`)

### 1-Year Commercial Subscription (e.g. 500 Users):
```bash
python3 generate_license.py --org "Inet Secure Labs" --users 500 --days 365 --out zclockid.lic
```

### Multi-Year Commercial Subscription (e.g. 1,000 Users, 3 Years):
```bash
python3 generate_license.py --org "Enterprise Corp" --users 1000 --days 1095 --out zclockid.lic
```

### Perpetual / Lifetime License:
```bash
python3 generate_license.py --org "Headquarters DC" --users 2500 --perpetual --out zclockid.lic
```

### Unlimited Users Perpetual License:
```bash
python3 generate_license.py --org "Enterprise Unlimited" --users 0 --perpetual --out zclockid.lic
```

---

## 3. Uploading to ZclockID Appliance

1. Log into the ZclockID Web Console (`https://<appliance-ip>/`).
2. Go to **Security & Management > License**.
3. Drag and drop `zclockid.lic` into the upload zone or click **Upload License**.
4. The system validates the signature in real time and updates the subscribed user capacity and validity countdown immediately.
