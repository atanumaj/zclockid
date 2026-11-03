#!/usr/bin/env bash
# ==============================================================================
# ZclockID Appliance Automated Bootstrap Installer
# Converts a raw Ubuntu LTS VM (22.04+) into a purpose-built ZclockID Domain Controller.
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

# Check Ubuntu version (>= 22.04)
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        log_warn "This installer is targeted for Ubuntu LTS. Detected: ${NAME}."
    fi
    OS_VER_MAJOR=$(echo "$VERSION_ID" | cut -d. -f1)
    if [[ "$OS_VER_MAJOR" -lt 22 ]]; then
        log_error "Ubuntu 22.04 LTS or newer is required. Detected: ${VERSION_ID}."
        exit 1
    fi
    log_info "Detected OS: ${PRETTY_NAME}"
fi

log_info "Starting ZclockID Modular Appliance Installation..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || echo "/tmp")"
PACKAGE_FILE=""

# Check if a built deb package exists locally
LOCAL_DEB=$(ls -1 "${SCRIPT_DIR}"/zclockid_*_all.deb 2>/dev/null | head -n1 || true)
if [[ -n "$LOCAL_DEB" && -f "$LOCAL_DEB" ]]; then
    log_info "Found local ZclockID Debian package: ${LOCAL_DEB}"
    PACKAGE_FILE="$LOCAL_DEB"
elif [[ -f "${SCRIPT_DIR}/package/build-deb.sh" ]]; then
    log_info "Building local thin .deb package from repository source..."
    "${SCRIPT_DIR}/package/build-deb.sh" "1.0.0"
    PACKAGE_FILE=$(ls -1 "${SCRIPT_DIR}"/zclockid_*_all.deb 2>/dev/null | head -n1 || true)
fi

# If package not found locally, download from GitHub Releases
if [[ -z "$PACKAGE_FILE" || ! -f "$PACKAGE_FILE" ]]; then
    log_info "Downloading latest ZclockID thin package from GitHub Releases..."
    TMP_DEB="/tmp/zclockid_latest_all.deb"
    DEB_URL="https://github.com/atanude/Inet-ZclockID/releases/latest/download/zclockid_1.0.0_all.deb"
    
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$DEB_URL" -o "$TMP_DEB" || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$DEB_URL" -O "$TMP_DEB" || true
    fi

    if [[ -f "$TMP_DEB" && -s "$TMP_DEB" ]]; then
        PACKAGE_FILE="$TMP_DEB"
    else
        log_error "Could not find local or remote zclockid .deb package."
        log_error "Please build it with './package/build-deb.sh' or specify package path."
        exit 1
    fi
fi

# 2. Update APT cache and install thin package with all upstream dependencies
log_info "Installing ZclockID via APT (upstream Samba, BIND9, FreeRADIUS, Chrony, Nginx)..."
export DEBIAN_FRONTEND=noninteractive

# Pre-seed kerberos prompts so apt never hangs interactively
echo "krb5-config krb5-config/default_realm string INET.NET" | debconf-set-selections 2>/dev/null || true
echo "krb5-config krb5-config/kerberos_servers string 127.0.0.1" | debconf-set-selections 2>/dev/null || true
echo "krb5-config krb5-config/admin_server string 127.0.0.1" | debconf-set-selections 2>/dev/null || true

apt-get update -y
apt-get install -y --no-install-recommends "$PACKAGE_FILE"

PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

echo -e "\n${GREEN}=================================================================${NC}"
echo -e "${GREEN}       ZclockID Modular Appliance Installation Completed!        ${NC}"
echo -e "${GREEN}=================================================================${NC}"
echo -e "Web Management Console: ${GREEN}https://${PRIMARY_IP}/${NC}"
echo -e "Initial Setup Wizard:   ${GREEN}https://${PRIMARY_IP}/setup.html${NC}"
echo -e "User Self-Registration: ${GREEN}https://${PRIMARY_IP}/register.html${NC}"
echo -e "Headless REST API:      ${BLUE}http://${PRIMARY_IP}:8000/docs${NC}"
echo -e "\nAll upstream services (Samba, FreeRADIUS, BIND9, Chrony, Nginx) are linked to standard Ubuntu security updates."
echo -e "${GREEN}=================================================================${NC}\n"
