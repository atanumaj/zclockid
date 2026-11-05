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

echo "=== Step 3: Preserving and linking SQLite Database & Certificates ==="
if [ -f "/var/lib/zclockid/zclockid.db" ] && [ ! -f "${ZROOT}/data/zclockid.db" ]; then
    cp -a /var/lib/zclockid/zclockid.db "${ZROOT}/data/zclockid.db"
    echo "Copied existing database to ${ZROOT}/data/zclockid.db"
fi
# Maintain backward compatibility link
mkdir -p /var/lib/zclockid
ln -sfn "${ZROOT}/data/zclockid.db" /var/lib/zclockid/zclockid.db 2>/dev/null || true

# Preserve and link SSL certificates
if [ -d "/etc/zclockid/certs" ] && [ ! -d "${ZROOT}/data/certs" ]; then
    mkdir -p "${ZROOT}/data"
    cp -a /etc/zclockid/certs "${ZROOT}/data/certs"
fi
ln -sfn "${ZROOT}/data/certs" /etc/zclockid/certs 2>/dev/null || true

echo "=== Step 4: Ensuring Sysadmin Overrides Directory & Engine Inclusions ==="
touch "${ZROOT}/config/overrides.d/smb-custom.conf" \
      "${ZROOT}/config/overrides.d/radius-custom.conf" \
      "${ZROOT}/config/overrides.d/bind-custom.conf"

# Include overrides in Samba
if [ -f "/etc/samba/smb.conf" ] && ! grep -q 'smb-custom.conf' /etc/samba/smb.conf; then
    echo -e "\n# Native sysadmin overrides drop-in\ninclude = ${ZROOT}/config/overrides.d/smb-custom.conf" >> /etc/samba/smb.conf
fi

# Include overrides in BIND9
if [ -f "/etc/bind/named.conf.local" ] && ! grep -q 'bind-custom.conf' /etc/bind/named.conf.local; then
    echo -e "\n// Native sysadmin overrides drop-in\ninclude \"${ZROOT}/config/overrides.d/bind-custom.conf\";" >> /etc/bind/named.conf.local
fi

# Include overrides in FreeRADIUS
if [ -f "/etc/freeradius/3.0/clients.conf" ]; then
    sed -i '/radius-custom.conf/d' /etc/freeradius/3.0/clients.conf
    echo '# Native sysadmin overrides drop-in' >> /etc/freeradius/3.0/clients.conf
    echo '$INCLUDE /zclockid/config/overrides.d/radius-custom.conf' >> /etc/freeradius/3.0/clients.conf
fi

# Update Nginx web root to /zclockid/web
if [ -f "/etc/nginx/sites-available/zclockid.conf" ]; then
    sed -i 's|/opt/zclockid/web|/zclockid/web|g' /etc/nginx/sites-available/zclockid.conf
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
fi

# Update zclock-azuresync service path
if [ -f "/etc/systemd/system/zclock-azuresync.service" ]; then
    sed -i 's|/opt/zclockid/scripts/zclock-azuresync.py|/zclockid/daemons/zclock-azuresync.py|g' /etc/systemd/system/zclock-azuresync.service
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

echo "=== Step 5: Setting directory permissions & AppArmor profiles ==="
chown -R root:root "${ZROOT}"
chmod 755 "${ZROOT}" "${ZROOT}/config" "${ZROOT}/config/overrides.d" "${ZROOT}/api" "${ZROOT}/web" "${ZROOT}/scripts" "${ZROOT}/daemons"
chmod 644 "${ZROOT}/config/overrides.d/"* 2>/dev/null || true
chmod 700 "${ZROOT}/data" "${ZROOT}/logs"

# Configure AppArmor for BIND9 if present
if [ -d "/etc/apparmor.d/local" ] && [ -f "/etc/apparmor.d/local/usr.sbin.named" ]; then
    if ! grep -q "${ZROOT}/\*\* r," /etc/apparmor.d/local/usr.sbin.named; then
        echo "${ZROOT}/** r," >> /etc/apparmor.d/local/usr.sbin.named
        apparmor_parser -r /etc/apparmor.d/usr.sbin.named 2>/dev/null || true
    fi
fi

echo "=== Unified /zclockid/ environment provisioned successfully! ==="
