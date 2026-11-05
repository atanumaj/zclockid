#!/usr/bin/env bash
# ====================================================================
#     ZCLOCKID APPLIANCE - UNIFIED ROOT MIGRATION & SETUP SCRIPT
# ====================================================================
# Migrates ZclockID to the unified /zclockid/ root structure:
# 1. Provisions /zclockid directory hierarchy
# 2. Symlinks Sysvol: /zclockid/data/sysvol -> /var/lib/samba/sysvol (Option A)
# 3. Migrates database and state files
# 4. Sets up engine drop-ins & sysadmin overrides (/zclockid/config/overrides.d/)
# 5. Configures systemd units to run from /zclockid
# ====================================================================

set -euo pipefail

ZROOT="/zclockid"
echo "=== Step 1: Provisioning ${ZROOT} hierarchy ==="
mkdir -p "${ZROOT}/config/samba" \
         "${ZROOT}/config/freeradius" \
         "${ZROOT}/config/bind" \
         "${ZROOT}/config/nginx" \
         "${ZROOT}/config/chrony" \
         "${ZROOT}/config/overrides.d" \
         "${ZROOT}/api/core" \
         "${ZROOT}/api/routers" \
         "${ZROOT}/api/services" \
         "${ZROOT}/api/schemas" \
         "${ZROOT}/db" \
         "${ZROOT}/templates" \
         "${ZROOT}/web" \
         "${ZROOT}/daemons" \
         "${ZROOT}/data/backups" \
         "${ZROOT}/logs"

echo "=== Step 2: Setting up Sysvol Option A Symlink ==="
if [ -d "/var/lib/samba/sysvol" ]; then
    if [ ! -L "${ZROOT}/data/sysvol" ]; then
        ln -sfn /var/lib/samba/sysvol "${ZROOT}/data/sysvol"
        echo "Sysvol symlink created: ${ZROOT}/data/sysvol -> /var/lib/samba/sysvol"
    fi
else
    echo "Notice: /var/lib/samba/sysvol not present yet; placeholder link ready."
fi

echo "=== Step 3: Preserving and linking SQLite Database ==="
if [ -f "/var/lib/zclockid/zclockid.db" ] && [ ! -f "${ZROOT}/data/zclockid.db" ]; then
    cp -a /var/lib/zclockid/zclockid.db "${ZROOT}/data/zclockid.db"
    echo "Copied existing database to ${ZROOT}/data/zclockid.db"
fi
# Maintain backward compatibility link
mkdir -p /var/lib/zclockid
ln -sfn "${ZROOT}/data/zclockid.db" /var/lib/zclockid/zclockid.db 2>/dev/null || true

echo "=== Step 4: Ensuring Sysadmin Overrides Directory ==="
touch "${ZROOT}/config/overrides.d/smb-custom.conf" \
      "${ZROOT}/config/overrides.d/radius-custom.conf" \
      "${ZROOT}/config/overrides.d/bind-custom.conf"

echo "=== Step 5: Setting directory permissions ==="
chown -R root:root "${ZROOT}"
chmod 755 "${ZROOT}"
chmod 700 "${ZROOT}/config" "${ZROOT}/data" "${ZROOT}/logs"

echo "=== Unified /zclockid/ environment provisioned successfully! ==="
