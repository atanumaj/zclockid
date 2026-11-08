#!/usr/bin/env bash
# ==============================================================================
# ZclockID Appliance Automated Background OS & Debian Package Updater
# Detached daemon for non-interactive system package upgrades
# ==============================================================================

set -o pipefail

LOG_FILE="/var/log/zclock-os-update.log"
STATUS_FILE="/var/run/zclock-os-update.status"
MODE="${1:-all}"

echo "UPGRADING" > "${STATUS_FILE}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

echo "=== ZclockID Debian/Ubuntu OS Package Upgrade Initiated at $(date) ===" > "${LOG_FILE}"
log "Upgrade Target Mode: ${MODE}"

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

log "Refreshing APT package repositories..."
if ! apt-get update >> "${LOG_FILE}" 2>&1; then
    log "WARNING: apt-get update encountered notices. Proceeding with package evaluation..."
fi

log "Applying non-interactive Debian/Ubuntu package upgrades (including kernel dependencies)..."
if apt-get -y --with-new-pkgs -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade >> "${LOG_FILE}" 2>&1; then
    log "SUCCESS: System packages upgraded successfully."
    
    # Invalidate stale package cache
    rm -f /var/lib/zclockid/upgradable_packages.json 2>/dev/null || true

    # Check if a reboot is needed
    if [ -f "/var/run/reboot-required" ]; then
        log "NOTICE: System reboot is required to apply kernel or core system updates."
        echo "COMPLETED_REBOOT_REQUIRED" > "${STATUS_FILE}"
    else
        echo "COMPLETED" > "${STATUS_FILE}"
    fi
else
    log "WARNING: Initial upgrade encountered issues. Attempting dependency auto-repair..."
    if apt-get install -f -y >> "${LOG_FILE}" 2>&1; then
        log "SUCCESS: Dependencies resolved."
        echo "COMPLETED" > "${STATUS_FILE}"
    else
        log "CRITICAL: Upgrade failed with errors. Check /var/log/zclock-os-update.log"
        echo "FAILED" > "${STATUS_FILE}"
        exit 1
    fi
fi

log "=== OS Package Upgrade Finished ==="
exit 0
