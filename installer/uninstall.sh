#!/usr/bin/env bash
# ==============================================================================
# ZclockID Appliance Complete Uninstallation & Purge Script
# Completely removes ZclockID packages, daemons, configs, and database files
# ==============================================================================

set -o pipefail

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

if [[ $EUID -ne 0 ]]; then
    log_error "This uninstaller must be run as root. Run with: sudo bash $0"
    exit 1
fi

echo -e "${RED}=================================================================${NC}"
echo -e "${RED}      ZclockID Appliance Complete Uninstallation & Purge        ${NC}"
echo -e "${RED}=================================================================${NC}"
echo -e "WARNING: This will completely stop and purge ZclockID services,"
echo -e "appliance databases, and local configurations.\n"

if [[ "$1" != "-y" && "$1" != "--yes" ]]; then
    read -p "Are you sure you want to completely uninstall ZclockID? (yes/no): " CONFIRM
    if [[ "$CONFIRM" != "yes" && "$CONFIRM" != "y" ]]; then
        echo "Uninstallation aborted."
        exit 0
    fi
fi

log_info "1. Stopping and disabling ZclockID daemons..."
systemctl stop zclock-api.service zclock-sysvold.service zclock-azuresync.service zclock-exporter.service 2>/dev/null || true
systemctl disable zclock-api.service zclock-sysvold.service zclock-azuresync.service zclock-exporter.service 2>/dev/null || true

log_info "2. Removing ZclockID package via APT..."
export DEBIAN_FRONTEND=noninteractive
apt-get purge -y zclockid 2>/dev/null || dpkg -P zclockid 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true

log_info "3. Removing systemd service definitions..."
rm -f /etc/systemd/system/zclock-*.service
systemctl daemon-reload

log_info "4. Removing Nginx ingress reverse proxy configuration..."
rm -f /etc/nginx/sites-enabled/zclockid.conf
rm -f /etc/nginx/sites-available/zclockid.conf
# Restore default nginx site if nginx is present
if [ -f /etc/nginx/sites-available/default ] && [ ! -f /etc/nginx/sites-enabled/default ]; then
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default || true
fi
systemctl restart nginx 2>/dev/null || true

log_info "5. Removing Chrony ZclockID custom snippets..."
rm -f /etc/chrony/conf.d/zclockid-ntp-server.conf
rm -f /etc/chrony/sources.d/zclockid-upstream.sources
systemctl restart chrony 2>/dev/null || true

log_info "6. Restoring systemd-resolved DNSStubListener (Port 53)..."
if [ -f /etc/systemd/resolved.conf ]; then
    sed -i 's/^DNSStubListener=no/#DNSStubListener=yes/' /etc/systemd/resolved.conf
    systemctl restart systemd-resolved 2>/dev/null || true
fi

log_info "7. Removing telemetry helper executables..."
rm -f /usr/local/bin/zclock-telemetry.sh

log_info "8. Purging ZclockID directories, databases, and logs..."
rm -rf /opt/zclockid
rm -rf /zclockid
rm -rf /etc/zclockid
rm -rf /var/lib/zclockid
rm -rf /var/log/zclockid
rm -rf /var/backups/zclockid
rm -f /var/log/zclock-*.log
rm -f /var/run/zclock-*.status

log_info "9. Removing APT repository entry..."
rm -f /etc/apt/sources.list.d/zclockid.list
rm -f /etc/apt/apt.conf.d/90zclockid-noninteractive

log_info "10. Purging Active Directory Samba, BIND9, and Kerberos state..."
systemctl stop samba-ad-dc bind9 freeradius 2>/dev/null || true
rm -f /etc/samba/smb.conf*
rm -f /etc/krb5.conf*
rm -rf /var/lib/samba/private/*
rm -rf /var/lib/samba/bind-dns/*

log_success "ZclockID has been completely uninstalled and purged from this system!"
echo -e "${GREEN}System cleanup is 100% complete.${NC}\n"
