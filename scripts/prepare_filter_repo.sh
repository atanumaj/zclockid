#!/usr/bin/env bash
# ==============================================================================
# ZclockID Enterprise - Repository History Sanitization Script (git-filter-repo)
# ==============================================================================
# SAFETY WARNING:
# Do NOT run this script until:
# 1. Master license signing key has been rotated and deployed.
# 2. Live appliance console administrator credentials have been changed.
# 3. Full backup clones of ZclockID and zclockid-private have been archived.
#
# Usage:
#   OLD_CONSOLE_PASS="<old-pass>" ./scripts/prepare_filter_repo.sh /path/to/repo [public|private]
# ==============================================================================

set -euo pipefail

TARGET_DIR="${1:-.}"
REPO_TYPE="${2:-public}" # 'public' for ZclockID, 'private' for zclockid-private

echo "=== ZclockID History Sanitization Preparation ==="
echo "Target directory: ${TARGET_DIR}"
echo "Repository type:  ${REPO_TYPE}"

if ! command -v git-filter-repo >/dev/null 2>&1; then
    echo "ERROR: git-filter-repo is not installed."
    echo "Install via: pip install git-filter-repo  OR  brew install git-filter-repo"
    exit 1
fi

cd "${TARGET_DIR}"

# Ensure working directory is a clean git repository
if [ ! -d ".git" ]; then
    echo "ERROR: ${TARGET_DIR} is not a git repository root."
    exit 1
fi

# Create a secure temporary directory for rewrite expressions
SCRATCH_DIR="$(mktemp -d -t zclock-filter-XXXXXX)"
trap 'rm -rf "${SCRATCH_DIR}"' EXIT
EXPRESSIONS_FILE="${SCRATCH_DIR}/expressions.txt"

if [ "${REPO_TYPE}" = "public" ]; then
    echo "Configuring text replacements for public ZclockID repository..."

    # Guard: ensure gh-pages serves the current manifest before running rewrite
    MANIFEST_URL="https://raw.githubusercontent.com/atanumaj/zclockid/gh-pages/version-manifest.json"
    echo "Verifying remote manifest availability at ${MANIFEST_URL}..."
    REMOTE_MANIFEST="$(curl -sf "${MANIFEST_URL}" || true)"
    if [ -z "${REMOTE_MANIFEST}" ]; then
        echo "ERROR: Refusing to run git-filter-repo!"
        echo "The new publish location (${MANIFEST_URL}) is not reachable or returns non-200."
        echo "Ensure gh-pages branch has been pushed and serves the current manifest."
        exit 1
    fi

    # Guard: compare gh-pages manifest "version" with VERSION file
    CURRENT_VERSION="$(tr -d '[:space:]' < VERSION)"
    REMOTE_VERSION="$(echo "${REMOTE_MANIFEST}" | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n 1 | cut -d'"' -f4)"
    if [ "${REMOTE_VERSION}" != "${CURRENT_VERSION}" ]; then
        echo "ERROR: Refusing to run git-filter-repo!"
        echo "Remote manifest version ('${REMOTE_VERSION}') does not match local VERSION ('${CURRENT_VERSION}')."
        echo "Ensure gh-pages branch has been pushed with the latest release manifest."
        exit 1
    fi
    echo "Verified remote manifest is reachable on gh-pages and version '${REMOTE_VERSION}' matches VERSION."

    if [ -z "${OLD_CONSOLE_PASS:-}" ]; then
        echo -n "Enter old console admin password to scrub from history (input will be hidden): "
        read -rs OLD_CONSOLE_PASS
        echo ""
    fi

    if [ -z "${OLD_CONSOLE_PASS}" ]; then
        echo "ERROR: Old console password cannot be empty."
        exit 1
    fi

    # Format: <literal-regex>==><replacement>
    cat << EOF > "${EXPRESSIONS_FILE}"
${OLD_CONSOLE_PASS}==>SetupTestP@ssw0rd123!
EOF
    chmod 600 "${EXPRESSIONS_FILE}"

    echo "Running git-filter-repo to purge binary deb packages and redact credentials on master branch ONLY..."
    git filter-repo --force \
        --refs master \
        --invert-paths \
        --path apt-repo/pool \
        --path-glob '*.deb' \
        --path-glob '*.deb.sig' \
        --replace-text "${EXPRESSIONS_FILE}"

    # Assert gh-pages still lists the current .deb after master rewrite
    echo "Verifying gh-pages pool integrity on origin/gh-pages..."
    CURRENT_DEB="zclockid_${CURRENT_VERSION}_all.deb"
    if ! git ls-tree origin/gh-pages apt-repo/pool/main/ | grep -q "${CURRENT_DEB}"; then
        echo "ERROR: Post-rewrite assertion failed! ${CURRENT_DEB} missing from origin/gh-pages pool."
        exit 1
    fi
    echo "Post-rewrite assertion passed: origin/gh-pages still lists ${CURRENT_DEB}."

elif [ "${REPO_TYPE}" = "private" ]; then
    echo "Checking prerequisites for private zclockid-private repository..."

    KEY_ROTATED=false
    for arg in "$@"; do
        if [ "$arg" = "--key-rotated" ]; then
            KEY_ROTATED=true
            break
        fi
    done

    if [ "${KEY_ROTATED}" != "true" ]; then
        cat << 'EOF'
ERROR: Refusing to run git-filter-repo on private repository without key rotation!

Prerequisites for private-repo rewrite:
[ ] 1. Generate a new Ed25519 license keypair outside of git (or in a secure offline keystore):
       python3 keygen.py
[ ] 2. Update appliance public key: Copy the new zclockid_public_key.pem to
       ZclockID/api/core/license_public_key.pem and tag/release it in an appliance update.
[ ] 3. Re-issue and sign customer/appliance licenses with the new private key.
[ ] 4. Confirm appliances running the new version validate licenses with the new key.
[ ] 5. Ensure the new private key is stored outside git (.gitignore configured).

Once the signing key has been rotated and deployed to appliances, re-run this script with:
  ./scripts/prepare_filter_repo.sh /path/to/zclockid-private private --key-rotated
EOF
        exit 1
    fi

    echo "Configuring purge paths for private zclockid-private repository..."
    git filter-repo --force \
        --invert-paths \
        --path zclockid_private_key.pem \
        --path-glob '*.lic'
else
    echo "ERROR: Unknown repository type '${REPO_TYPE}'. Use 'public' or 'private'."
    exit 1
fi

echo "Pruning reflogs and packing rewritten objects..."
git reflog expire --expire=now --all || true
git gc --prune=now --aggressive

echo "=== Verification ==="
if command -v gitleaks >/dev/null 2>&1; then
    echo "Running Gitleaks post-rewrite verification (must exit 0)..."
    gitleaks detect --log-opts="--all" --verbose
else
    echo "ERROR: gitleaks CLI is required but not found in PATH." >&2
    exit 1
fi

echo ""
echo "Repository rewrite complete in ${TARGET_DIR}."
echo "Review the commit history with: git log -n 10 --stat"
if [ "${REPO_TYPE}" = "public" ]; then
    echo "When satisfied, push rewritten refs with: git push --force origin master"
else
    echo "When satisfied, push rewritten refs with: git push --force origin master"
fi
