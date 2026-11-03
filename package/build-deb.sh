#!/usr/bin/env bash
# ==============================================================================
# Build Debian (.deb) Package for ZclockID Appliance
# ==============================================================================

set -eo pipefail

PACKAGE_NAME="zclockid"
VERSION="${1:-1.0.0}"
ARCH="all"
DIST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="/tmp/zclockid-deb-build"

echo "================================================================="
echo "Building ${PACKAGE_NAME}_${VERSION}_${ARCH}.deb..."
echo "================================================================="

rm -rf "${BUILD_ROOT}"
mkdir -p "${BUILD_ROOT}/DEBIAN"
mkdir -p "${BUILD_ROOT}/opt/zclockid/api"
mkdir -p "${BUILD_ROOT}/opt/zclockid/scripts"
mkdir -p "${BUILD_ROOT}/opt/zclockid/web"
mkdir -p "${BUILD_ROOT}/etc/systemd/system"
mkdir -p "${BUILD_ROOT}/etc/nginx/sites-available"
mkdir -p "${BUILD_ROOT}/etc/chrony/conf.d"
mkdir -p "${BUILD_ROOT}/etc/chrony/sources.d"
mkdir -p "${BUILD_ROOT}/etc/zclockid/templates"
mkdir -p "${BUILD_ROOT}/var/lib/zclockid"
mkdir -p "${BUILD_ROOT}/var/backups/zclockid"

# 1. Copy package metadata
sed "s/^Version:.*/Version: ${VERSION}/" "${DIST_DIR}/package/debian/control" > "${BUILD_ROOT}/DEBIAN/control"
cp "${DIST_DIR}/package/debian/postinst" "${BUILD_ROOT}/DEBIAN/"
chmod 755 "${BUILD_ROOT}/DEBIAN/postinst"

# 2. Copy API backend
cp "${DIST_DIR}/api-prototype/main.py" "${BUILD_ROOT}/opt/zclockid/api/"
if [[ -f "${DIST_DIR}/api-prototype/requirements.txt" ]]; then
    cp "${DIST_DIR}/api-prototype/requirements.txt" "${BUILD_ROOT}/opt/zclockid/api/"
fi

# 3. Copy Daemons and Telemetry Scripts
cp "${DIST_DIR}/scripts/zclock-sysvold.py" "${BUILD_ROOT}/opt/zclockid/scripts/"
cp "${DIST_DIR}/scripts/zclock-telemetry.sh" "${BUILD_ROOT}/opt/zclockid/scripts/"
cp "${DIST_DIR}/scripts/zclock-azuresync.py" "${BUILD_ROOT}/opt/zclockid/scripts/"
cp "${DIST_DIR}/scripts/zclock-updater.sh" "${BUILD_ROOT}/opt/zclockid/scripts/"
chmod 755 "${BUILD_ROOT}/opt/zclockid/scripts/"*

# Write appliance VERSION file
echo "${VERSION}" > "${BUILD_ROOT}/opt/zclockid/VERSION"

# 4. Copy Web Console Assets
cp "${DIST_DIR}/web/index.html" "${BUILD_ROOT}/opt/zclockid/web/"
cp "${DIST_DIR}/web/login.html" "${BUILD_ROOT}/opt/zclockid/web/"
cp "${DIST_DIR}/web/register.html" "${BUILD_ROOT}/opt/zclockid/web/"
cp "${DIST_DIR}/web/setup.html" "${BUILD_ROOT}/opt/zclockid/web/"

# 5. Copy Configuration Templates
if [[ -f "${DIST_DIR}/config-templates/azure/azure-sync.json" ]]; then
    cp "${DIST_DIR}/config-templates/azure/azure-sync.json" "${BUILD_ROOT}/etc/zclockid/"
fi
if [[ -f "${DIST_DIR}/config-templates/nginx/zclockid.conf" ]]; then
    cp "${DIST_DIR}/config-templates/nginx/zclockid.conf" "${BUILD_ROOT}/etc/nginx/sites-available/"
fi
if [[ -f "${DIST_DIR}/config-templates/chrony/zclockid-ntp-server.conf" ]]; then
    cp "${DIST_DIR}/config-templates/chrony/zclockid-ntp-server.conf" "${BUILD_ROOT}/etc/chrony/conf.d/"
fi
if [[ -f "${DIST_DIR}/config-templates/chrony/zclockid-upstream.sources" ]]; then
    cp "${DIST_DIR}/config-templates/chrony/zclockid-upstream.sources" "${BUILD_ROOT}/etc/chrony/sources.d/"
fi
if [[ -f "${DIST_DIR}/config-templates/snmp/snmpd.conf" ]]; then
    cp "${DIST_DIR}/config-templates/snmp/snmpd.conf" "${BUILD_ROOT}/etc/zclockid/templates/"
fi
if [[ -f "${DIST_DIR}/config-templates/bind9/named.conf.options" ]]; then
    cp "${DIST_DIR}/config-templates/bind9/named.conf.options" "${BUILD_ROOT}/etc/zclockid/templates/"
fi
if [[ -d "${DIST_DIR}/config-templates/freeradius" ]]; then
    mkdir -p "${BUILD_ROOT}/etc/zclockid/templates/freeradius"
    cp -r "${DIST_DIR}/config-templates/freeradius/"* "${BUILD_ROOT}/etc/zclockid/templates/freeradius/"
fi

# 6. Copy systemd unit files
for svc in zclock-api.service zclock-sysvold.service zclock-azuresync.service; do
    if [[ -f "${DIST_DIR}/systemd/${svc}" ]]; then
        cp "${DIST_DIR}/systemd/${svc}" "${BUILD_ROOT}/etc/systemd/system/"
    fi
done

# 7. Build debian binary package
OUTPUT_DEB="${DIST_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "${BUILD_ROOT}" "${OUTPUT_DEB}"

echo "Debian package successfully built at: ${OUTPUT_DEB}"
ls -lh "${OUTPUT_DEB}"
rm -rf "${BUILD_ROOT}"
