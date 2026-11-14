#!/usr/bin/env bash
# ==============================================================================
# ZclockID Appliance Automated Background Package Updater
# Detached from main API process so service restarts do not interrupt the upgrade
# ==============================================================================

set -o pipefail

LOG_FILE="/var/log/zclock-update.log"
STATUS_FILE="/var/run/zclock-update.status"
DEB_PACKAGE="${1:-/var/lib/zclockid/updates/zclockid_update.deb}"

echo "UPDATING" > "${STATUS_FILE}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

echo "=== ZclockID Package Update Initiated at $(date) ===" > "${LOG_FILE}"
log "Update target package: ${DEB_PACKAGE}"

if [ ! -f "${DEB_PACKAGE}" ]; then
    log "ERROR: Target package file ${DEB_PACKAGE} not found!"
    echo "ERROR: Package file not found" > "${STATUS_FILE}"
    exit 1
fi

log "Inspecting package metadata via dpkg-deb..."
PKG_INFO=$(dpkg-deb -I "${DEB_PACKAGE}" 2>&1)
PKG_NAME=$(echo "${PKG_INFO}" | grep -E '^\s*Package:' | awk '{print $2}')
PKG_VER=$(echo "${PKG_INFO}" | grep -E '^\s*Version:' | awk '{print $2}')

log "Package Name: ${PKG_NAME:-unknown}, Version: ${PKG_VER:-unknown}"

if [ "${PKG_NAME}" != "zclockid" ]; then
    log "ERROR: Invalid package name '${PKG_NAME}'. Expected 'zclockid'."
    echo "ERROR: Invalid package (${PKG_NAME})" > "${STATUS_FILE}"
    exit 1
fi

KEYRING="${ZCLOCKID_KEYRING_PATH:-/usr/share/keyrings/zclockid-archive-keyring.gpg}"
SIG_FILE="${DEB_PACKAGE}.sig"

if [ ! -f "${KEYRING}" ]; then
    log "CRITICAL: Archive keyring ${KEYRING} not found! Cannot verify package cryptographically."
    echo "ERROR: Archive keyring missing" > "${STATUS_FILE}"
    exit 1
fi

if [ ! -f "${SIG_FILE}" ]; then
    log "CRITICAL: Package signature file ${SIG_FILE} not found! All updates must be cryptographically signed."
    echo "ERROR: Package signature missing" > "${STATUS_FILE}"
    exit 1
fi

log "Verifying package signature against ${KEYRING}..."
if ! gpgv --keyring "${KEYRING}" "${SIG_FILE}" "${DEB_PACKAGE}" >> "${LOG_FILE}" 2>&1; then
    log "ERROR: Package signature verification failed!"
    echo "ERROR: Invalid signature" > "${STATUS_FILE}"
    exit 1
fi
log "Package signature verified successfully."

log "Package validated successfully. Applying upgrade via dpkg..."

# Automated pre-update safety backup
log "Creating automated pre-update snapshot backup..."
BACKUP_DIR="/var/backups/zclockid"
mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}" 2>/dev/null || true
CURR_V=$(cat /opt/zclockid/VERSION 2>/dev/null || echo "pre-update")
BACKUP_TAR="${BACKUP_DIR}/zclockid-backup-v${CURR_V}-$(date +%Y%m%d%H%M%S).tar.gz"
(umask 077 && tar -czf "${BACKUP_TAR}" -C / var/lib/zclockid etc/zclockid 2>/dev/null || true)
chmod 600 "${BACKUP_TAR}" 2>/dev/null || true
log "Safety snapshot created at ${BACKUP_TAR}"

export DEBIAN_FRONTEND=noninteractive
if dpkg -i "${DEB_PACKAGE}" >> "${LOG_FILE}" 2>&1; then
    log "dpkg installation succeeded."
else
    log "dpkg reported dependency issues. Attempting repair with apt-get install -f -y..."
    if apt-get install -f -y >> "${LOG_FILE}" 2>&1; then
        log "apt-get dependency resolution succeeded."
    else
        log "ERROR: Failed to resolve dependencies for package."
        echo "ERROR: Dependency resolution failed" > "${STATUS_FILE}"
        exit 1
    fi
fi

# Ensure VERSION file is updated
echo "${PKG_VER}" > /opt/zclockid/VERSION 2>/dev/null || true

log "Verifying zclock-api service status..."
sleep 2

if systemctl is-active --quiet zclock-api.service; then
    log "SUCCESS: zclock-api service is active and responding."
    log "Appliance upgrade to v${PKG_VER} completed successfully!"
    echo "COMPLETED: v${PKG_VER}" > "${STATUS_FILE}"
else
    log "Service not yet active. Restarting zclock-api service..."
    systemctl daemon-reload >> "${LOG_FILE}" 2>&1 || true
    systemctl restart zclock-api.service >> "${LOG_FILE}" 2>&1 || true
    sleep 3
    if systemctl is-active --quiet zclock-api.service; then
        log "SUCCESS: zclock-api service recovered and active."
        echo "COMPLETED: v${PKG_VER}" > "${STATUS_FILE}"
    else
        log "CRITICAL: zclock-api service failed to restart. Check journalctl -u zclock-api."
        echo "ERROR: API service restart failed" > "${STATUS_FILE}"
        exit 1
    fi
fi

# Clean up temp file
rm -f "${DEB_PACKAGE}" 2>/dev/null || true
log "=== Update Complete ==="
exit 0
