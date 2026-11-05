"""
ZclockID SSL/TLS Certificate Management Router
Handles active certificate inspection, SAN-enabled self-signed generation, custom PEM/Key uploads, and CSR generation.
"""

import os
import shutil
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import PlainTextResponse

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from api.services.system_service import log_audit, run_cmd
from api.schemas.cert_schema import (
    SelfSignedCertRequest,
    CertUploadRequest,
    CsrGenerateRequest,
    ActiveCertDetailsResponse
)

router = APIRouter(prefix="/api/v1/certificates", tags=["SSL/TLS Certificate Management"])

PRIMARY_CERT_PATH = "/etc/zclockid/certs/appliance.crt"
PRIMARY_KEY_PATH = "/etc/zclockid/certs/appliance.key"
ALT_CERT_PATH = "/zclockid/data/certs/appliance.crt"
ALT_KEY_PATH = "/zclockid/data/certs/appliance.key"
PENDING_CSR_KEY_PATH = "/etc/zclockid/certs/pending_csr.key"

def get_cert_path() -> str:
    if os.path.exists(PRIMARY_CERT_PATH):
        return PRIMARY_CERT_PATH
    if os.path.exists(ALT_CERT_PATH):
        return ALT_CERT_PATH
    return PRIMARY_CERT_PATH

def sync_cert_files(cert_bytes: bytes, key_bytes: bytes):
    """Writes cert and key to both /etc/zclockid/certs and /zclockid/data/certs."""
    for c_path, k_path in [(PRIMARY_CERT_PATH, PRIMARY_KEY_PATH), (ALT_CERT_PATH, ALT_KEY_PATH)]:
        try:
            os.makedirs(os.path.dirname(c_path), exist_ok=True)
            with open(c_path, "wb") as f:
                f.write(cert_bytes)
            with open(k_path, "wb") as f:
                f.write(key_bytes)
            os.chmod(c_path, 0o644)
            os.chmod(k_path, 0o600)
        except Exception:
            pass

def reload_nginx_with_rollback(backup_cert: bytes, backup_key: bytes):
    """Tests Nginx syntax; if valid reloads, if invalid rolls back to backup."""
    code, stdout, stderr = run_cmd(["nginx", "-t"])
    if code != 0:
        # Rollback
        sync_cert_files(backup_cert, backup_key)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Nginx configuration test failed with new certificate: {stderr or stdout}. Rolled back to previous certificate."
        )
    run_cmd(["systemctl", "reload", "nginx"])

@router.get("/active", response_model=ActiveCertDetailsResponse)
def get_active_certificate():
    """Inspects the currently active SSL/TLS certificate powering the Web GUI and REST API."""
    cert_path = get_cert_path()
    if not os.path.exists(cert_path):
        raise HTTPException(status_code=404, detail=f"Active certificate file not found at {cert_path}")

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse active X.509 certificate: {str(e)}")

    now_utc = datetime.now(timezone.utc)
    valid_from = cert.not_valid_before_utc
    valid_to = cert.not_valid_after_utc
    days_remaining = (valid_to - now_utc).days

    # Extract SANs
    san_list = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                san_list.append(name.value)
            elif isinstance(name, x509.IPAddress):
                san_list.append(str(name.value))
    except Exception:
        pass

    # Status classification
    if days_remaining <= 0:
        cert_status = "EXPIRED"
    elif days_remaining <= 30:
        cert_status = "EXPIRING_SOON"
    else:
        cert_status = "VALID"

    is_self_signed = (cert.issuer == cert.subject)

    sig_alg = "SHA256"
    if cert.signature_hash_algorithm:
        sig_alg = cert.signature_hash_algorithm.name.upper()

    return ActiveCertDetailsResponse(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        valid_from=valid_from.strftime("%Y-%m-%d %H:%M:%S UTC"),
        valid_to=valid_to.strftime("%Y-%m-%d %H:%M:%S UTC"),
        days_remaining=days_remaining,
        san_list=san_list,
        signature_algorithm=sig_alg,
        serial_number=hex(cert.serial_number),
        is_self_signed=is_self_signed,
        status=cert_status
    )

@router.get("/download/active")
def download_active_certificate():
    """Downloads the active server certificate PEM for importing into trust stores."""
    cert_path = get_cert_path()
    if not os.path.exists(cert_path):
        raise HTTPException(status_code=404, detail="Active certificate not found.")
    with open(cert_path, "r") as f:
        content = f.read()
    return PlainTextResponse(content, media_type="application/x-pem-file", headers={
        "Content-Disposition": "attachment; filename=zclockid-appliance.crt"
    })

@router.post("/self-signed")
def generate_self_signed_certificate(req: SelfSignedCertRequest):
    """
    Generates and installs a new high-security RSA self-signed SSL/TLS certificate
    with custom Subject Alternative Names (SANs) for all LAN IP addresses and hostnames.
    """
    # Read backups
    cert_path = get_cert_path()
    key_path = PRIMARY_KEY_PATH if os.path.exists(PRIMARY_KEY_PATH) else ALT_KEY_PATH
    backup_cert = b""
    backup_key = b""
    if os.path.exists(cert_path):
        with open(cert_path, "rb") as f:
            backup_cert = f.read()
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            backup_key = f.read()

    # Determine Common Name
    cn = req.common_name or os.uname().nodename or "inet-zclockid"

    # Generate RSA Private Key (2048-bit)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Build SAN entries
    san_entries = []
    # Always include CN
    san_entries.append(x509.DNSName(cn))

    for item in req.san_list:
        item = item.strip()
        if not item:
            continue
        try:
            ip_obj = ipaddress.ip_address(item)
            san_entries.append(x509.IPAddress(ip_obj))
        except ValueError:
            san_entries.append(x509.DNSName(item))

    # Deduplicate SAN entries
    unique_sans = []
    seen = set()
    for entry in san_entries:
        val = str(entry.value)
        if val not in seen:
            seen.add(val)
            unique_sans.append(entry)

    name_attributes = [
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, req.organization or "Inet Secure Labs"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "ZclockID Appliance")
    ]
    subject = issuer = x509.Name(name_attributes)

    now_utc = datetime.now(timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_utc - timedelta(minutes=5))
        .not_valid_after(now_utc + timedelta(days=req.validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(unique_sans), critical=False)
    )

    certificate = cert_builder.sign(private_key, hashes.SHA256())

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    sync_cert_files(cert_pem, key_pem)
    reload_nginx_with_rollback(backup_cert, backup_key)

    log_audit("CERT_SELF_SIGNED_GENERATED", "admin", cn, "SUCCESS", {
        "validity_days": req.validity_days,
        "sans": [str(s.value) for s in unique_sans]
    })

    return {
        "status": "success",
        "message": f"New self-signed certificate generated and activated for {cn}.",
        "valid_days": req.validity_days,
        "san_count": len(unique_sans)
    }

@router.post("/upload")
def upload_custom_certificate(req: CertUploadRequest):
    """
    Validates and installs an enterprise PEM certificate and private key.
    Ensures that the private key matches the certificate public key before updating Nginx.
    """
    # 1. Parse Certificate
    try:
        cert_bytes = req.cert_pem.strip().encode("utf-8")
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid Certificate PEM: {str(e)}")

    # 2. Parse Private Key
    try:
        key_bytes = req.key_pem.strip().encode("utf-8")
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid Private Key PEM: {str(e)}")

    # 3. Verify public key match
    cert_pub_numbers = cert.public_key().public_numbers()
    key_pub_numbers = private_key.public_key().public_numbers()
    if cert_pub_numbers != key_pub_numbers:
        raise HTTPException(
            status_code=400,
            detail="Public key mismatch: The provided private key does not match the public key in the certificate."
        )

    # 4. Assemble full chain if chain_pem was provided
    full_cert_pem = req.cert_pem.strip() + "\n"
    if req.chain_pem and req.chain_pem.strip():
        full_cert_pem += req.chain_pem.strip() + "\n"
    full_cert_bytes = full_cert_pem.encode("utf-8")

    # Read backups
    cert_path = get_cert_path()
    key_path = PRIMARY_KEY_PATH if os.path.exists(PRIMARY_KEY_PATH) else ALT_KEY_PATH
    backup_cert = b""
    backup_key = b""
    if os.path.exists(cert_path):
        with open(cert_path, "rb") as f:
            backup_cert = f.read()
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            backup_key = f.read()

    # Write files and test reload
    sync_cert_files(full_cert_bytes, key_bytes)
    reload_nginx_with_rollback(backup_cert, backup_key)

    cn = "Certificate"
    try:
        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attr:
            cn = cn_attr[0].value
    except Exception:
        pass

    log_audit("CERT_CUSTOM_UPLOADED", "admin", str(cn), "SUCCESS", {"subject": cert.subject.rfc4514_string()})
    return {
        "status": "success",
        "message": f"Enterprise certificate for '{cn}' activated successfully.",
        "subject": cert.subject.rfc4514_string()
    }

@router.post("/csr")
def generate_csr(req: CsrGenerateRequest):
    """
    Generates a new private key and Certificate Signing Request (CSR) in PEM format
    for submission to enterprise Public Key Infrastructure (PKI) or public CAs.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    name_attributes = [
        x509.NameAttribute(NameOID.COMMON_NAME, req.common_name.strip()),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, req.organization.strip()),
        x509.NameAttribute(NameOID.LOCALITY_NAME, req.city.strip()),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, req.state.strip()),
        x509.NameAttribute(NameOID.COUNTRY_NAME, req.country.strip().upper()),
    ]
    if req.organizational_unit:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, req.organizational_unit.strip()))

    subject = x509.Name(name_attributes)

    san_entries = [x509.DNSName(req.common_name.strip())]
    for item in req.san_list:
        item = item.strip()
        if not item:
            continue
        try:
            ip_obj = ipaddress.ip_address(item)
            san_entries.append(x509.IPAddress(ip_obj))
        except ValueError:
            san_entries.append(x509.DNSName(item))

    csr_builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
    )
    csr = csr_builder.sign(private_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Save private key to pending CSR key path
    try:
        with open(PENDING_CSR_KEY_PATH, "wb") as f:
            f.write(key_pem)
        os.chmod(PENDING_CSR_KEY_PATH, 0o600)
    except Exception:
        pass

    log_audit("CSR_GENERATED", "admin", req.common_name, "SUCCESS", {"organization": req.organization})
    return {
        "status": "success",
        "csr_pem": csr_pem,
        "private_key_saved": True,
        "message": "Certificate Signing Request generated. Copy and submit the CSR to your CA. The private key has been saved on the appliance ready for your signed certificate upload."
    }
