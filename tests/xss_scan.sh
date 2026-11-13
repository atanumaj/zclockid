#!/usr/bin/env bash
# tests/xss_scan.sh: Audit web/ for unescaped innerHTML interpolations and unsafe onclick handlers
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WEB_DIR="$ROOT_DIR/web"

VIOLATIONS=0

# 1. Grep web/ for innerHTML with ${ without escapeHtml(
INNERHTML_HITS=$(grep -rn "innerHTML" "$WEB_DIR" 2>/dev/null | grep '\${' | grep -v 'escapeHtml(' || true)
if [ -n "$INNERHTML_HITS" ]; then
    echo "Violation: innerHTML with unescaped interpolation:"
    echo "$INNERHTML_HITS"
    VIOLATIONS=$((VIOLATIONS + $(echo "$INNERHTML_HITS" | wc -l)))
fi

# 2. Grep web/ for onclick handlers containing ${ interpolation
ONCLICK_HITS=$(grep -rn 'onclick=".*${' "$WEB_DIR" 2>/dev/null || true)
if [ -n "$ONCLICK_HITS" ]; then
    echo "Violation: onclick handler with \${ interpolation (must use data-* + addEventListener):"
    echo "$ONCLICK_HITS"
    VIOLATIONS=$((VIOLATIONS + $(echo "$ONCLICK_HITS" | wc -l)))
fi

# 3. Python scan over all web files for unescaped innerHTML interpolation
PYTHON_HITS=$(python3 -c "
import os, sys
web_dir = sys.argv[1]
hits = []
for root, _, files in os.walk(web_dir):
    for f in sorted(files):
        if not (f.endswith('.js') or f.endswith('.html')):
            continue
        path = os.path.join(root, f)
        rel_path = os.path.relpath(path, web_dir)
        with open(path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        for idx, line in enumerate(lines, 1):
            if 'innerHTML' in line and '\${' in line and 'escapeHtml(' not in line:
                hits.append(f'{rel_path}:{idx}: {line.strip()}')
for h in hits:
    print(h)
" "$WEB_DIR")

if [ -n "$PYTHON_HITS" ]; then
    echo "Violation: unescaped innerHTML template literals:"
    echo "$PYTHON_HITS"
    VIOLATIONS=$((VIOLATIONS + $(echo "$PYTHON_HITS" | wc -l)))
fi

if [ "$VIOLATIONS" -gt 0 ]; then
    echo "Total violations found: $VIOLATIONS"
    exit 1
else
    echo "XSS scan passed: 0 violations found."
    exit 0
fi
