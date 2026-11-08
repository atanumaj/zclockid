#!/usr/bin/env python3
"""
ZclockID Master Keypair Generator (Vendor Tool)
==============================================
Generates the asymmetric Ed25519 cryptographic keypair used to issue
and verify ZclockID Enterprise Licenses.

* KEEP THE PRIVATE KEY (zclockid_private_key.pem) IN YOUR PRIVATE REPO/OFFLINE SECURE STORAGE!
* The PUBLIC KEY (zclockid_public_key.pem) is bundled into ZclockID appliances.
"""

import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

KEY_DIR = Path(__file__).resolve().parent

PRIVATE_KEY_PATH = KEY_DIR / "zclockid_private_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "zclockid_public_key.pem"

def generate_keypair():
    if PRIVATE_KEY_PATH.exists():
        print(f"Warning: Private key already exists at {PRIVATE_KEY_PATH}")
        confirm = input("Overwrite existing master keypair? (y/N): ").strip().lower()
        if confirm != 'y':
            print("Aborted.")
            return

    # Generate Ed25519 private key
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize private key to PEM (PKCS8, unencrypted or encrypted)
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM (SubjectPublicKeyInfo)
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    PRIVATE_KEY_PATH.write_bytes(priv_bytes)
    PRIVATE_KEY_PATH.chmod(0o600)
    PUBLIC_KEY_PATH.write_bytes(pub_bytes)

    print(f"Master Ed25519 Private Key saved to: {PRIVATE_KEY_PATH} (permissions: 0600)")
    print(f"Master Ed25519 Public Key saved to:  {PUBLIC_KEY_PATH}")
    print("\nPublic Key PEM:\n" + pub_bytes.decode())

if __name__ == "__main__":
    generate_keypair()
