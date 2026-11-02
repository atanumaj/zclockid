#!/usr/bin/env bash
# ==============================================================================
# ZclockID Appliance Automated Bootstrap Installer
# Converts a raw Ubuntu LTS VM into a purpose-built ZclockID Domain Controller.
# ==============================================================================

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. Pre-flight Checks
if [[ $EUID -ne 0 ]]; then
    log_error "This installer must be run as root (use sudo)."
    exit 1
fi

log_info "Starting ZclockID Appliance Bootstrap Installation..."

# 2. Disable Native Host Firewalls (UFW / Firewalld)
# Domain controllers require dozens of dynamic RPC ports (49152-65535), Kerberos, SMB, and LDAP.
# Host-level packet filters create subtle replication and authentication deadlocks.
log_info "Teardown of host-level firewalls (UFW / Firewalld)..."
if command -v ufw >/dev/null 2>&1; then
    ufw disable || true
    systemctl stop ufw || true
    systemctl disable ufw || true
    systemctl mask ufw || true
    log_success "UFW disabled and masked."
fi

if systemctl is-active --quiet firewalld; then
    systemctl stop firewalld || true
    systemctl disable firewalld || true
    log_success "Firewalld disabled."
fi

# 3. Decouple systemd-resolved from Port 53
# systemd-resolved binds a stub listener to 127.0.0.53:53, which blocks BIND9.
# We disable the stub listener while strictly PRESERVING host network configuration (Netplan).
log_info "Decoupling systemd-resolved stub listener from Port 53..."
if [[ -f /etc/systemd/resolved.conf ]]; then
    sed -i 's/^#*DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
    systemctl restart systemd-resolved || true
    log_success "systemd-resolved stub listener disabled. Port 53 released for BIND9."
fi

# 4. Install Core System Packages
log_info "Updating apt cache and installing core engine dependencies..."
export DEBIAN_FRONTEND=noninteractive
echo "krb5-config krb5-config/default_realm string CORP.EXAMPLE.COM" | debconf-set-selections 2>/dev/null || true
echo "krb5-config krb5-config/kerberos_servers string dc1.corp.example.com" | debconf-set-selections 2>/dev/null || true
echo "krb5-config krb5-config/admin_server string dc1.corp.example.com" | debconf-set-selections 2>/dev/null || true
apt-get update -y
apt-get install -y --no-install-recommends \
    samba \
    samba-ad-dc \
    samba-ad-provision \
    samba-dsdb-modules \
    samba-vfs-modules \
    smbclient \
    winbind \
    libpam-winbind \
    libnss-winbind \
    krb5-user \
    bind9 \
    bind9utils \
    bind9-dnsutils \
    bind9-libs \
    freeradius \
    freeradius-utils \
    freeradius-ldap \
    nginx \
    snmpd \
    snmp \
    chrony \
    acl \
    attr \
    python3 \
    python3-fastapi \
    python3-uvicorn \
    python3-pydantic \
    python3-psutil \
    python3-pip \
    python3-venv \
    curl \
    git \
    jq

log_success "Core engine packages installed."

# 5. Mask and Stop Standard Samba File Services (AD DC uses samba-ad-dc)
log_info "Disabling standard smbd/nmbd in favor of samba-ad-dc..."
systemctl stop smbd nmbd winbind || true
systemctl disable smbd nmbd winbind || true
systemctl mask smbd nmbd winbind || true

# 6. Service Group & Permission Tuning
log_info "Configuring service accounts and privilege groups..."

# FreeRADIUS access to Samba Winbind privileged pipe
if getent group winbindd_priv >/dev/null; then
    usermod -aG winbindd_priv freerad || true
fi

# Chrony access to MS-SNTP signing socket
mkdir -p /var/lib/samba/ntp_signd
chown -R root:_chrony /var/lib/samba/ntp_signd || true
chmod 750 /var/lib/samba/ntp_signd || true

# BIND access to Samba DLZ databases
mkdir -p /var/lib/samba/private
chown -R root:bind /var/lib/samba/private || true
chmod 750 /var/lib/samba/private || true

# 7. Deploy ZclockID Application Code
log_info "Deploying ZclockID binaries, scripts, web dashboard, and systemd units..."
INSTALL_DIR="/opt/zclockid"
mkdir -p "${INSTALL_DIR}/api" "${INSTALL_DIR}/scripts" "${INSTALL_DIR}/web" "/etc/zclockid/certs"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Generate self-signed TLS cert for appliance if not present
if [[ ! -f /etc/zclockid/certs/appliance.crt ]]; then
    log_info "Generating initial appliance TLS certificates..."
    openssl req -x509 -nodes -days 1825 -newkey rsa:2048 \
        -keyout /etc/zclockid/certs/appliance.key \
        -out /etc/zclockid/certs/appliance.crt \
        -subj "/CN=$(hostname -f 2>/dev/null || echo 'zclockid.local')/O=Inet Secure Labs/OU=ZclockID" >/dev/null 2>&1 || true
fi

# Copy Web Dashboard & Registration Portal
cp "${SCRIPT_DIR}/web/index.html" "${INSTALL_DIR}/web/"
cp "${SCRIPT_DIR}/web/register.html" "${INSTALL_DIR}/web/"

# Copy API files
cp "${SCRIPT_DIR}/api-prototype/main.py" "${INSTALL_DIR}/api/"
cp "${SCRIPT_DIR}/api-prototype/requirements.txt" "${INSTALL_DIR}/api/"

# Copy Scripts
cp "${SCRIPT_DIR}/scripts/zclock-sysvold.py" "${INSTALL_DIR}/scripts/"
cp "${SCRIPT_DIR}/scripts/zclock-telemetry.sh" "${INSTALL_DIR}/scripts/"
cp "${SCRIPT_DIR}/scripts/zclock-azuresync.py" "${INSTALL_DIR}/scripts/"
chmod +x "${INSTALL_DIR}/scripts/"*

# Copy Azure Sync baseline config if not exists
if [[ ! -f /etc/zclockid/azure-sync.json && -f "${SCRIPT_DIR}/config-templates/azure/azure-sync.json" ]]; then
    cp "${SCRIPT_DIR}/config-templates/azure/azure-sync.json" /etc/zclockid/
fi

# Configure Nginx
if [[ -f "${SCRIPT_DIR}/config-templates/nginx/zclockid.conf" ]]; then
    cp "${SCRIPT_DIR}/config-templates/nginx/zclockid.conf" /etc/nginx/sites-available/
    rm -f /etc/nginx/sites-enabled/default || true
    ln -sf /etc/nginx/sites-available/zclockid.conf /etc/nginx/sites-enabled/
    systemctl restart nginx || true
    log_success "Nginx ingress proxy configured on Port 80 and 443."
fi

# Python requirements are provided natively via apt
log_info "Verifying Python dependencies for ZclockID API..."
python3 -c "import fastapi, uvicorn, pydantic, psutil; print('All Python dependencies verified.')"

# Copy Systemd Services
cp "${SCRIPT_DIR}/systemd/zclock-api.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/systemd/zclock-sysvold.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable zclock-api.service
systemctl restart zclock-api.service

log_success "ZclockID Headless REST API service started on port 8000."

# 8. Summary Notice
echo -e "\n${GREEN}=================================================================${NC}"
echo -e "${GREEN}       ZclockID Appliance Bootstrap Installation Completed!      ${NC}"
echo -e "${GREEN}=================================================================${NC}"
echo -e "Host Network Configuration: ${YELLOW}Preserved intact (Netplan untouched)${NC}"
echo -e "Host Firewalls:             ${YELLOW}Disabled and masked (UFW)${NC}"
echo -e "Port 53 Status:             ${GREEN}Released for BIND9 DLZ${NC}"
echo -e "Management REST API:        ${GREEN}http://<host-ip>:8000/docs${NC}"
echo -e "Engines Ready for Domain Provisioning:"
echo -e "  - Samba AD DC (samba-ad-dc)"
echo -e "  - BIND9 DLZ (with native DoH)"
echo -e "  - FreeRADIUS (with ntlm_auth)"
echo -e "  - Net-SNMP Telemetry"
echo -e "  - Sysvol NTACL Self-Healing Daemon"
echo -e "${GREEN}=================================================================${NC}\n"

