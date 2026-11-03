#!/usr/bin/env bash
# ==============================================================================
# ZclockID Appliance Automated Background Package Updater
# Detached from main API process so service restarts do not interrupt the upgrade
# ==============================================================================

set -o pipefail

LOG_FILE="/var/log/zclock-update.log"
STATUS_FILE="/var/run/zclock-update.status"
DEB_PACKAGE="${1:-/tmp/zclockid_update.deb}"

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

log "Package validated successfully. Applying upgrade via dpkg..."

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
