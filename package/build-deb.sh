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
mkdir -p "${BUILD_ROOT}/usr/share/keyrings"

# 1. Copy package metadata and archive signing keyring
cp "${DIST_DIR}/package/debian/control" "${BUILD_ROOT}/DEBIAN/control"
sed -i '' "s/^Version:.*/Version: ${VERSION}/" "${BUILD_ROOT}/DEBIAN/control" 2>/dev/null || sed -i "s/^Version:.*/Version: ${VERSION}/" "${BUILD_ROOT}/DEBIAN/control"
cp "${DIST_DIR}/package/debian/postinst" "${BUILD_ROOT}/DEBIAN/"
chmod 755 "${BUILD_ROOT}/DEBIAN/postinst"

if [[ -f "${DIST_DIR}/package/keyrings/zclockid-archive-keyring.gpg" ]]; then
    cp "${DIST_DIR}/package/keyrings/zclockid-archive-keyring.gpg" "${BUILD_ROOT}/usr/share/keyrings/"
    chmod 644 "${BUILD_ROOT}/usr/share/keyrings/zclockid-archive-keyring.gpg"
fi

# 2. Copy API backend (Full modular FastAPI application)
cp -r "${DIST_DIR}/api/"* "${BUILD_ROOT}/opt/zclockid/api/"
if [[ -d "${DIST_DIR}/config" ]]; then
    mkdir -p "${BUILD_ROOT}/opt/zclockid/config"
    cp -r "${DIST_DIR}/config/"* "${BUILD_ROOT}/opt/zclockid/config/"
fi

# 3. Build & Install Native Go Daemons
mkdir -p "${BUILD_ROOT}/opt/zclockid/bin"
if [[ -d "${DIST_DIR}/daemons/go" ]] && command -v go >/dev/null 2>&1; then
    echo "Compiling native Go daemons (zclock-sysvold, zclock-exporter)..."
    (cd "${DIST_DIR}/daemons/go" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "${BUILD_ROOT}/opt/zclockid/bin/zclock-sysvold" ./cmd/zclock-sysvold)
    (cd "${DIST_DIR}/daemons/go" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "${BUILD_ROOT}/opt/zclockid/bin/zclock-exporter" ./cmd/zclock-exporter)
    chmod 755 "${BUILD_ROOT}/opt/zclockid/bin/"*
fi

# Copy Daemons and Telemetry Scripts
cp "${DIST_DIR}/scripts/zclock-sysvold.py" "${BUILD_ROOT}/opt/zclockid/scripts/"
cp "${DIST_DIR}/scripts/zclock-telemetry.sh" "${BUILD_ROOT}/opt/zclockid/scripts/"
cp "${DIST_DIR}/scripts/zclock-azuresync.py" "${BUILD_ROOT}/opt/zclockid/scripts/"
cp "${DIST_DIR}/scripts/zclock-updater.sh" "${BUILD_ROOT}/opt/zclockid/scripts/"
cp "${DIST_DIR}/scripts/zclock-os-updater.sh" "${BUILD_ROOT}/opt/zclockid/scripts/"
chmod 755 "${BUILD_ROOT}/opt/zclockid/scripts/"*

# Write appliance VERSION file
echo "${VERSION}" > "${BUILD_ROOT}/opt/zclockid/VERSION"

# 4. Build Tailwind CSS with Pinned Standalone CLI (No Node runtime on appliance)
TAILWIND_CLI_VER="v3.4.17"
TAILWIND_BIN="/tmp/tailwindcss-linux-x64"
EXPECTED_SHA256="7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4"

if [[ -f "${TAILWIND_BIN}" ]]; then
    ACTUAL_SHA256="$(sha256sum "${TAILWIND_BIN}" 2>/dev/null | awk '{print $1}' || shasum -a 256 "${TAILWIND_BIN}" 2>/dev/null | awk '{print $1}')"
    if [[ "${ACTUAL_SHA256}" != "${EXPECTED_SHA256}" ]]; then
        rm -f "${TAILWIND_BIN}"
    fi
fi

if [[ ! -f "${TAILWIND_BIN}" ]]; then
    echo "Downloading pinned standalone Tailwind CLI (${TAILWIND_CLI_VER})..."
    curl -sL "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_CLI_VER}/tailwindcss-linux-x64" -o "${TAILWIND_BIN}" 2>/dev/null || true
    chmod +x "${TAILWIND_BIN}" 2>/dev/null || true
fi

if [[ -x "${TAILWIND_BIN}" ]] && "${TAILWIND_BIN}" --help >/dev/null 2>&1; then
    ACTUAL_SHA256="$(sha256sum "${TAILWIND_BIN}" 2>/dev/null | awk '{print $1}' || shasum -a 256 "${TAILWIND_BIN}" 2>/dev/null | awk '{print $1}')"
    if [[ "${ACTUAL_SHA256}" != "${EXPECTED_SHA256}" ]]; then
        echo "ERROR: Tailwind CLI SHA-256 verification failed! Expected ${EXPECTED_SHA256}, got ${ACTUAL_SHA256}" >&2
        exit 1
    fi
    echo "Verified Tailwind standalone CLI SHA-256 (${ACTUAL_SHA256})"
    echo "Building web/css/tailwind.css with standalone CLI..."
    (cd "${DIST_DIR}" && "${TAILWIND_BIN}" -c tailwind.config.js -i web/css/tailwind-input.css -o web/css/tailwind.css --minify)
elif [[ -f "${DIST_DIR}/web/css/tailwind.css" ]]; then
    echo "Using pre-built web/css/tailwind.css..."
else
    echo "ERROR: web/css/tailwind.css missing and standalone Tailwind CLI unavailable." >&2
    exit 1
fi

# 5. Copy Web Console Assets
cp -r "${DIST_DIR}/web/"* "${BUILD_ROOT}/opt/zclockid/web/"

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
for svc in zclock-api.service zclock-sysvold.service zclock-azuresync.service zclock-exporter.service; do
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
