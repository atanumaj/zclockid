#!/usr/bin/env python3
"""
ZclockID Enterprise License Generator (Vendor Tool)
===================================================
Issues cryptographically signed 'zclockid.lic' license certificates using
the master Ed25519 private key.

Usage:
    python3 generate_license.py --org "Acme Corp" --users 500 --days 365 --out zclockid.lic
    python3 generate_license.py --org "Gov Entity" --users 2500 --perpetual --out zclockid.lic
"""

import sys
import os
import json
import base64
import random
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

KEY_DIR = Path(__file__).resolve().parent
DEFAULT_PRIV_KEY = KEY_DIR / "zclockid_private_key.pem"

def create_license_payload(org: str, max_users: int, expiry_date: str, is_perpetual: bool, license_id: str, tier: str, features: list):
    now_utc = datetime.now(timezone.utc)
    return {
        "license_id": license_id,
        "product": "ZclockID Enterprise",
        "organization": org,
        "tier": tier,
        "max_users": int(max_users),
        "issued_date": now_utc.strftime("%Y-%m-%d"),
        "issued_timestamp": int(now_utc.timestamp()),
        "expiry_date": "PERPETUAL" if is_perpetual else expiry_date,
        "is_perpetual": is_perpetual,
        "features": features,
        "version": "1.0"
    }

def sign_payload(payload_dict: dict, private_key: ed25519.Ed25519PrivateKey) -> str:
    # Deterministic JSON serialization with sorted keys
    canonical_json = json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature = private_key.sign(canonical_json)

    # Encode payload and signature
    payload_b64 = base64.b64encode(canonical_json).decode('ascii')
    sig_b64 = base64.b64encode(signature).decode('ascii')

    # Armored Certificate Format
    license_body = f"{payload_b64}.{sig_b64}"
    # Wrap in lines of 64 chars
    wrapped_lines = [license_body[i:i+64] for i in range(0, len(license_body), 64)]
    wrapped_content = "\n".join(wrapped_lines)

    license_pem = (
        "-----BEGIN ZCLOCKID LICENSE-----\n"
        f"{wrapped_content}\n"
        "-----END ZCLOCKID LICENSE-----\n"
    )
    return license_pem

def parse_args():
    parser = argparse.ArgumentParser(description="Generate cryptographically signed ZclockID license files.")
    parser.add_argument("--org", required=True, help="Organization or customer name")
    parser.add_argument("--users", type=int, default=500, help="Maximum allowed users (0 = Unlimited, default: 500)")
    parser.add_argument("--days", type=int, default=None, help="Validity duration in days from today")
    parser.add_argument("--expiry", type=str, default=None, help="Explicit expiration date in YYYY-MM-DD format")
    parser.add_argument("--perpetual", action="store_true", help="Issue a non-expiring perpetual license")
    parser.add_argument("--id", type=str, default=None, help="Custom License Serial Number (optional)")
    parser.add_argument("--tier", type=str, default="Enterprise", help="License tier name (default: Enterprise)")
    parser.add_argument("--features", type=str, default="all", help="Comma-separated feature list (default: all)")
    parser.add_argument("--private-key", type=str, default=str(DEFAULT_PRIV_KEY), help="Path to Ed25519 private key")
    parser.add_argument("--out", type=str, default="zclockid.lic", help="Output file path (default: zclockid.lic)")
    return parser.parse_args()

def main():
    args = parse_args()

    priv_path = Path(args.private_key)
    if not priv_path.exists():
        print(f"Error: Private key not found at {priv_path}.", file=sys.stderr)
        print("Run 'python3 keygen.py' first to generate your master keypair.", file=sys.stderr)
        sys.exit(1)

    # Load private key
    priv_bytes = priv_path.read_bytes()
    private_key = serialization.load_pem_private_key(priv_bytes, password=None)

    # Determine expiry date
    now_utc = datetime.now(timezone.utc)
    if args.perpetual:
        expiry_date = "PERPETUAL"
        is_perpetual = True
    elif args.expiry:
        expiry_date = args.expiry
        is_perpetual = False
    elif args.days:
        exp_dt = now_utc + timedelta(days=args.days)
        expiry_date = exp_dt.strftime("%Y-%m-%d")
        is_perpetual = False
    else:
        # Default 365 days
        exp_dt = now_utc + timedelta(days=365)
        expiry_date = exp_dt.strftime("%Y-%m-%d")
        is_perpetual = False

    # License ID
    lic_id = args.id or f"ZCLK-{now_utc.year}-{random.randint(100000, 999999)}"

    # Features
    feats = [f.strip() for f in args.features.split(",") if f.strip()]

    # Build and sign
    payload = create_license_payload(
        org=args.org,
        max_users=args.users,
        expiry_date=expiry_date,
        is_perpetual=is_perpetual,
        license_id=lic_id,
        tier=args.tier,
        features=feats
    )

    signed_license = sign_payload(payload, private_key)

    out_path = Path(args.out)
    out_path.write_text(signed_license, encoding="utf-8")

    user_label = "Unlimited" if args.users == 0 else f"{args.users:,} Users"
    validity_label = "Perpetual" if is_perpetual else f"Until {expiry_date}"

    print("=================================================================")
    print("        ZCLOCKID ENTERPRISE LICENSE GENERATED SUCCESSFULLY        ")
    print("=================================================================")
    print(f"License ID:     {lic_id}")
    print(f"Organization:   {args.org}")
    print(f"User Capacity:  {user_label}")
    print(f"Validity:       {validity_label}")
    print(f"Tier:           {args.tier}")
    print(f"Output File:    {out_path.resolve()}")
    print("=================================================================\n")
    print(signed_license)

if __name__ == "__main__":
    main()
