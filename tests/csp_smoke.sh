#!/usr/bin/env bash
#
# tests/csp_smoke.sh - Content Security Policy (CSP) Regression Smoke Test
#
# Runs headless Chrome against ZclockID web views and validates that no
# Content Security Policy violations are emitted to stderr.
#
set -eo pipefail

HOST="${1:-192.168.1.41}"
TOKEN="${2:-}"

# Normalize host to base URL
if [[ "$HOST" == http* ]]; then
    BASE_URL="${HOST%/}"
else
    BASE_URL="https://${HOST%/}"
fi

# Detect Chrome or Chromium binary
CHROME=""
if [ -n "$CHROME_BIN" ] && [ -x "$CHROME_BIN" ]; then
    CHROME="$CHROME_BIN"
elif [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
    CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
elif command -v google-chrome &>/dev/null; then
    CHROME="google-chrome"
elif command -v google-chrome-stable &>/dev/null; then
    CHROME="google-chrome-stable"
elif command -v chromium &>/dev/null; then
    CHROME="chromium"
elif command -v chromium-browser &>/dev/null; then
    CHROME="chromium-browser"
fi

if [ -z "$CHROME" ]; then
    echo "ERROR: Chrome or Chromium binary not found in standard paths." >&2
    echo "Please set CHROME_BIN=/path/to/chrome and re-run." >&2
    exit 1
fi

echo "================================================================="
echo " ZclockID CSP Smoke Test"
echo " Chrome binary: $CHROME"
echo " Target host:   $BASE_URL"
echo "================================================================="

VIOLATIONS_FOUND=0

test_csp_url() {
    local target_url="$1"
    local label="$2"
    local stderr_tmp
    stderr_tmp=$(mktemp)

    echo -n "Testing $label... "

    # Execute headless Chrome and capture stderr
    "$CHROME" \
        --headless=new \
        --ignore-certificate-errors \
        --enable-logging=stderr \
        --dump-dom \
        "$target_url" >/dev/null 2>"$stderr_tmp" || true

    # Filter out known non-CSP platform warnings (e.g. CVDisplayLink on macOS)
    if grep -i "Content Security Policy" "$stderr_tmp" >/dev/null 2>&1; then
        echo "FAILED!"
        echo "-----------------------------------------------------------------" >&2
        echo "CSP violation detected on $label ($target_url):" >&2
        grep -i "Content Security Policy" "$stderr_tmp" >&2
        echo "-----------------------------------------------------------------" >&2
        VIOLATIONS_FOUND=$((VIOLATIONS_FOUND + 1))
    else
        echo "PASSED (0 CSP violations)"
    fi

    rm -f "$stderr_tmp"
}

# 1. Unauthenticated Public Surface Tests
test_csp_url "$BASE_URL/" "Root Appliance UI (Unauthenticated)"
test_csp_url "$BASE_URL/login.html" "Login Interface"
test_csp_url "$BASE_URL/register.html" "Self-Registration Portal"
test_csp_url "$BASE_URL/password-reset.html" "Password Reset Portal"

# 2. Authenticated Tab Tests via Playwright (tests/csp_smoke.py)
if [ -n "${ZCLOCK_USER:-}" ] && [ -n "${ZCLOCK_PASS:-}" ]; then
    echo ""
    echo "Running Playwright authenticated tab smoke tests (tests/csp_smoke.py)..."
    PYTHON_BIN="python3"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -x "/Users/atanu/Documents/GitHub/zclockid-private/.venv/bin/python" ]; then
        PYTHON_BIN="/Users/atanu/Documents/GitHub/zclockid-private/.venv/bin/python"
    elif [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
        PYTHON_BIN="$VIRTUAL_ENV/bin/python"
    fi
    "$PYTHON_BIN" "$SCRIPT_DIR/csp_smoke.py" "$HOST"
else
    echo ""
    echo "Notice: ZCLOCK_USER and ZCLOCK_PASS not set in environment."
    echo "To run authenticated tab tests via Playwright, provide:"
    echo "  ZCLOCK_USER=admin ZCLOCK_PASS=... ./tests/csp_smoke.sh $HOST"
fi

echo "================================================================="
if [ "$VIOLATIONS_FOUND" -gt 0 ]; then
    echo "CSP Smoke Test FAILED: $VIOLATIONS_FOUND violation(s) detected!" >&2
    exit 1
fi

echo "CSP Smoke Test PASSED: All tested routes comply with CSP!"
exit 0
