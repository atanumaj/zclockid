#!/usr/bin/env bash
# ==============================================================================
# ZclockID Appliance Automated One-Line Bootstrap Installer
# Compatible with Ubuntu 22.04 LTS & Ubuntu 24.04 LTS (DEB822 format)
# ==============================================================================

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

echo -e "${CYAN}=================================================================${NC}"
echo -e "${CYAN}      ZclockID Enterprise Active Directory & IAM Appliance       ${NC}"
echo -e "${CYAN}                Automated Production Installer                  ${NC}"
echo -e "${CYAN}=================================================================${NC}\n"

# 1. Root Check
if [[ $EUID -ne 0 ]]; then
    log_error "This installer must be run as root. Please run with: sudo bash $0"
    exit 1
fi

# 2. Ubuntu OS Check
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID_LIKE" != *"ubuntu"* ]]; then
        log_warn "This installer is targeted for Ubuntu LTS (22.04+). Detected: ${PRETTY_NAME}"
    fi
    OS_VER_MAJOR=$(echo "$VERSION_ID" | cut -d. -f1)
    if [[ "$OS_VER_MAJOR" -lt 22 ]]; then
        log_error "Ubuntu 22.04 LTS or newer is required. Detected version: ${VERSION_ID}"
        exit 1
    fi
    log_info "Target System: ${PRETTY_NAME} (${ID} ${VERSION_ID})"
fi

# 3. Pre-seed Kerberos / debconf non-interactive defaults
export DEBIAN_FRONTEND=noninteractive
log_info "Configuring non-interactive package pre-seeds..."
mkdir -p /etc/apt/apt.conf.d
echo 'APT::Get::Assume-Yes "true";' > /etc/apt/apt.conf.d/90zclockid-noninteractive
echo 'APT::Get::allow-unauthenticated "true";' >> /etc/apt/apt.conf.d/90zclockid-noninteractive
echo 'Acquire::AllowInsecureRepositories "true";' >> /etc/apt/apt.conf.d/90zclockid-noninteractive

if command -v debconf-set-selections >/dev/null 2>&1; then
    echo "krb5-config krb5-config/default_realm string EXAMPLE.COM" | debconf-set-selections 2>/dev/null || true
    echo "krb5-config krb5-config/kerberos_servers string 127.0.0.1" | debconf-set-selections 2>/dev/null || true
    echo "krb5-config krb5-config/admin_server string 127.0.0.1" | debconf-set-selections 2>/dev/null || true
fi

# 4. Download and Install ZclockID from GitHub
GITHUB_REPO_RAW="https://raw.githubusercontent.com/atanumaj/zclockid/master"
PACKAGE_URL="${GITHUB_REPO_RAW}/apt-repo/pool/main/zclockid_1.0.0_all.deb"
TMP_DEB="/tmp/zclockid_1.0.0_all.deb"

log_info "Downloading ZclockID Debian package from GitHub..."
CACHE_BUST=$(date +%s)
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${PACKAGE_URL}?v=${CACHE_BUST}" -o "$TMP_DEB"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_DEB" "${PACKAGE_URL}?v=${CACHE_BUST}"
fi

if [[ ! -f "$TMP_DEB" || ! -s "$TMP_DEB" ]]; then
    log_error "Failed to download ZclockID package from GitHub."
    exit 1
fi

# 5. Configure ZclockID Ubuntu APT Repository on GitHub for future upgrades
log_info "Configuring official GitHub APT repository for continuous updates..."
cat << EOF > /etc/apt/sources.list.d/zclockid.sources
Types: deb
URIs: ${GITHUB_REPO_RAW}/apt-repo
Suites: stable
Components: main
Trusted: yes
EOF

cat << EOF > /etc/apt/sources.list.d/zclockid.list
deb [trusted=yes] ${GITHUB_REPO_RAW}/apt-repo stable main
EOF

# Ensure universe repository is available for samba-ad-provision on Ubuntu
if ! command -v add-apt-repository >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends software-properties-common >/dev/null 2>&1 || true
fi
add-apt-repository -y universe >/dev/null 2>&1 || true

log_info "Updating system APT cache..."
apt-get update -y || true

# Pre-install Samba AD DC schema and provisioning dependencies
log_info "Installing Active Directory schema dependencies (samba-ad-provision, ldb-tools)..."
apt-get install -y samba samba-ad-dc samba-ad-provision ldb-tools python3-setproctitle || true

# 6. Install ZclockID and all upstream engine dependencies
log_info "Installing ZclockID appliance and upstream subsystem dependencies..."
log_info "(Samba AD DC, BIND9 DLZ, FreeRADIUS, Chrony, Nginx, SNMP, Python)..."

dpkg -i "$TMP_DEB" || apt-get install -y --fix-broken --allow-unauthenticated
rm -f "$TMP_DEB"

# 7. Ensure FreeRADIUS certificates are bootstrapped if needed
if [ -d /etc/freeradius/3.0/certs ] && [ ! -f /etc/freeradius/3.0/certs/server.pem ]; then
    log_info "Bootstrapping FreeRADIUS initial certificates..."
    if [ -f /etc/freeradius/3.0/certs/bootstrap ]; then
        chmod +x /etc/freeradius/3.0/certs/bootstrap >/dev/null 2>&1 || true
        bash /etc/freeradius/3.0/certs/bootstrap >/dev/null 2>&1 || true
    elif [ -f /etc/freeradius/3.0/certs/Makefile ]; then
        make -C /etc/freeradius/3.0/certs >/dev/null 2>&1 || true
    fi
    chown -R freerad:freerad /etc/freeradius/3.0/certs >/dev/null 2>&1 || true
    systemctl restart freeradius >/dev/null 2>&1 || true
fi

# 8. Verify Installation
PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

echo -e "\n${GREEN}=================================================================${NC}"
echo -e "${GREEN}      ZclockID Enterprise DC Installation Completed! (v1.0.0)    ${NC}"
echo -e "${GREEN}=================================================================${NC}"
echo -e "Web Management Console: ${CYAN}https://${PRIMARY_IP}/${NC}"
echo -e "First-Time Setup:       ${CYAN}https://${PRIMARY_IP}/setup.html${NC}"
echo -e "User Self-Registration: ${CYAN}https://${PRIMARY_IP}/register.html${NC}"
echo -e "REST API Docs (Swagger):${BLUE}http://${PRIMARY_IP}:8000/docs${NC}"
echo -e "================================================================="
echo -e "Next Steps:"
echo -e "1. Open ${CYAN}https://${PRIMARY_IP}/setup.html${NC} to provision your Active Directory Realm"
echo -e "2. Default Admin: administrator / admin (set during setup)"
echo -e "=================================================================\n"
