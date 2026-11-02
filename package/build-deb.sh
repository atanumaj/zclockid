#!/usr/bin/env bash
# ==============================================================================
# Build Debian (.deb) Package for ZclockID Appliance
# ==============================================================================

set -eo pipefail

PACKAGE_NAME="zclockid"
VERSION="1.0.0"
ARCH="amd64"
DIST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="/tmp/zclockid-deb-build"

echo "Building ${PACKAGE_NAME}_${VERSION}_${ARCH}.deb..."

rm -rf "${BUILD_ROOT}"
mkdir -p "${BUILD_ROOT}/DEBIAN"
mkdir -p "${BUILD_ROOT}/opt/zclockid/api"
mkdir -p "${BUILD_ROOT}/opt/zclockid/scripts"
mkdir -p "${BUILD_ROOT}/opt/zclockid/web"
mkdir -p "${BUILD_ROOT}/etc/systemd/system"
mkdir -p "${BUILD_ROOT}/etc/nginx/sites-available"
mkdir -p "${BUILD_ROOT}/etc/zclockid"

# Copy package metadata
cp "${DIST_DIR}/package/debian/control" "${BUILD_ROOT}/DEBIAN/"
cp "${DIST_DIR}/package/debian/postinst" "${BUILD_ROOT}/DEBIAN/"
chmod 755 "${BUILD_ROOT}/DEBIAN/postinst"

# Copy payload
cp "${DIST_DIR}/api-prototype/main.py" "${BUILD_ROOT}/opt/zclockid/api/"
cp "${DIST_DIR}/api-prototype/requirements.txt" "${BUILD_ROOT}/opt/zclockid/api/"
cp "${DIST_DIR}/scripts/zclock-sysvold.py" "${BUILD_ROOT}/opt/zclockid/scripts/"
cp "${DIST_DIR}/scripts/zclock-telemetry.sh" "${BUILD_ROOT}/opt/zclockid/scripts/"
cp "${DIST_DIR}/scripts/zclock-azuresync.py" "${BUILD_ROOT}/opt/zclockid/scripts/"
chmod 755 "${BUILD_ROOT}/opt/zclockid/scripts/"*
cp "${DIST_DIR}/web/index.html" "${BUILD_ROOT}/opt/zclockid/web/"
cp "${DIST_DIR}/web/register.html" "${BUILD_ROOT}/opt/zclockid/web/"
cp "${DIST_DIR}/config-templates/azure/azure-sync.json" "${BUILD_ROOT}/etc/zclockid/"

# Copy Nginx Ingress template
cp "${DIST_DIR}/config-templates/nginx/zclockid.conf" "${BUILD_ROOT}/etc/nginx/sites-available/"

# Copy systemd unit files
cp "${DIST_DIR}/systemd/zclock-api.service" "${BUILD_ROOT}/etc/systemd/system/"
cp "${DIST_DIR}/systemd/zclock-sysvold.service" "${BUILD_ROOT}/etc/systemd/system/"

# Build debian binary package
OUTPUT_DEB="${DIST_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --build "${BUILD_ROOT}" "${OUTPUT_DEB}"

echo "Debian package successfully built at: ${OUTPUT_DEB}"
rm -rf "${BUILD_ROOT}"

