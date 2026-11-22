#!/usr/bin/env bash
# tests/xss_scan.sh: Comprehensive XSS, CSP & Inline-Execution Audit for web/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WEB_DIR="$ROOT_DIR/web"

VIOLATIONS=0

echo "=== Running ZclockID Static Security & CSP Compliance Scan ==="

# 1. Check for unescaped innerHTML interpolations
PYTHON_INNERHTML_HITS=$(python3 -c "
import os, sys
web_dir = sys.argv[1]
hits = []
for root, _, files in os.walk(web_dir):
    if 'vendor' in root:
        continue
    for f in sorted(files):
        if not (f.endswith('.js') or f.endswith('.html')):
            continue
        path = os.path.join(root, f)
        rel_path = os.path.relpath(path, web_dir)
        with open(path, 'r', encoding='utf-8') as file:
            for idx, line in enumerate(file, 1):
                if 'innerHTML' in line and '\${' in line and 'escapeHtml(' not in line:
                    hits.append(f'{rel_path}:{idx}: {line.strip()}')
for h in hits:
    print(h)
" "$WEB_DIR")

if [ -n "$PYTHON_INNERHTML_HITS" ]; then
    echo "Violation: unescaped innerHTML template literals:"
    echo "$PYTHON_INNERHTML_HITS"
    VIOLATIONS=$((VIOLATIONS + $(echo "$PYTHON_INNERHTML_HITS" | wc -l)))
fi

# 2. Check for any on[a-z]+= attributes in HTML and JS files (excluding vendor)
ON_ATTR_HITS=$(python3 -c "
import os, sys, re
web_dir = sys.argv[1]
hits = []
for root, _, files in os.walk(web_dir):
    if 'vendor' in root:
        continue
    for f in sorted(files):
        if not (f.endswith('.html') or f.endswith('.js')):
            continue
        path = os.path.join(root, f)
        rel_path = os.path.relpath(path, web_dir)
        with open(path, 'r', encoding='utf-8') as file:
            for idx, line in enumerate(file, 1):
                # Match inline event handler attributes like onclick=, onchange=, onsubmit=, etc.
                if re.search(r'\bon[a-z]+\s*=', line, re.IGNORECASE):
                    hits.append(f'{rel_path}:{idx}: {line.strip()}')
for h in hits:
    print(h)
" "$WEB_DIR")

if [ -n "$ON_ATTR_HITS" ]; then
    echo "Violation: inline event handler attribute (on*=) found:"
    echo "$ON_ATTR_HITS"
    VIOLATIONS=$((VIOLATIONS + $(echo "$ON_ATTR_HITS" | wc -l)))
fi

# 3. Check for any inline <script> tags without src in HTML
INLINE_SCRIPT_HITS=$(python3 -c "
import os, sys, re
web_dir = sys.argv[1]
hits = []
for root, _, files in os.walk(web_dir):
    if 'vendor' in root:
        continue
    for f in sorted(files):
        if not f.endswith('.html'):
            continue
        path = os.path.join(root, f)
        rel_path = os.path.relpath(path, web_dir)
        with open(path, 'r', encoding='utf-8') as file:
            content = file.read()
        for m in re.finditer(r'<script(?![^>]*\bsrc\s*=)[^>]*>', content, re.IGNORECASE):
            hits.append(f'{rel_path}: inline <script> without src detected')
for h in hits:
    print(h)
" "$WEB_DIR")

if [ -n "$INLINE_SCRIPT_HITS" ]; then
    echo "Violation: inline <script> tag without src found:"
    echo "$INLINE_SCRIPT_HITS"
    VIOLATIONS=$((VIOLATIONS + $(echo "$INLINE_SCRIPT_HITS" | wc -l)))
fi

# 4. Check for any <style> blocks or style= attributes in web/ (excluding vendor)
STYLE_HITS=$(python3 -c "
import os, sys, re
web_dir = sys.argv[1]
hits = []
for root, _, files in os.walk(web_dir):
    if 'vendor' in root:
        continue
    for f in sorted(files):
        if not (f.endswith('.html') or f.endswith('.js')):
            continue
        path = os.path.join(root, f)
        rel_path = os.path.relpath(path, web_dir)
        with open(path, 'r', encoding='utf-8') as file:
            for idx, line in enumerate(file, 1):
                if re.search(r'<style\b', line, re.IGNORECASE):
                    hits.append(f'{rel_path}:{idx}: <style> tag found')
                elif re.search(r'\bstyle\s*=', line, re.IGNORECASE):
                    hits.append(f'{rel_path}:{idx}: style= attribute found')
for h in hits:
    print(h)
" "$WEB_DIR")

if [ -n "$STYLE_HITS" ]; then
    echo "Violation: inline <style> block or style= attribute found:"
    echo "$STYLE_HITS"
    VIOLATIONS=$((VIOLATIONS + $(echo "$STYLE_HITS" | wc -l)))
fi

# 5. Check for eval, new Function, and setTimeout(string) in web/js/ (excluding vendor)
DANGEROUS_EVAL_HITS=$(python3 -c "
import os, sys, re
web_dir = sys.argv[1]
hits = []
for root, _, files in os.walk(web_dir):
    if 'vendor' in root:
        continue
    for f in sorted(files):
        if not (f.endswith('.html') or f.endswith('.js')):
            continue
        path = os.path.join(root, f)
        rel_path = os.path.relpath(path, web_dir)
        with open(path, 'r', encoding='utf-8') as file:
            for idx, line in enumerate(file, 1):
                clean = line.strip()
                if clean.startswith('//') or clean.startswith('/*'):
                    continue
                if re.search(r'\beval\s*\(', line):
                    hits.append(f'{rel_path}:{idx}: eval() found')
                elif re.search(r'new\s+Function\s*\(', line):
                    hits.append(f'{rel_path}:{idx}: new Function() found')
                elif re.search(r'setTimeout\s*\(\s*[\x27\x22\x60]', line):
                    hits.append(f'{rel_path}:{idx}: setTimeout(string) found')
for h in hits:
    print(h)
" "$WEB_DIR")

if [ -n "$DANGEROUS_EVAL_HITS" ]; then
    echo "Violation: dangerous dynamic evaluation found:"
    echo "$DANGEROUS_EVAL_HITS"
    VIOLATIONS=$((VIOLATIONS + $(echo "$DANGEROUS_EVAL_HITS" | wc -l)))
fi

# 6. Check that nothing in web/ reads a token from URLSearchParams or location
URL_TOKEN_HITS=$(python3 -c "
import os, sys, re
web_dir = sys.argv[1]
hits = []
for root, _, files in os.walk(web_dir):
    if 'vendor' in root:
        continue
    for f in sorted(files):
        if not (f.endswith('.js') or f.endswith('.html')):
            continue
        path = os.path.join(root, f)
        rel_path = os.path.relpath(path, web_dir)
        with open(path, 'r', encoding='utf-8') as file:
            for idx, line in enumerate(file, 1):
                if re.search(r'URLSearchParams.*\.get\([\"\']token[\"\']\)', line) or re.search(r'\.get\([\"\']token[\"\']\)', line):
                    hits.append(f'{rel_path}:{idx}: {line.strip()}')
                elif 'location' in line and 'token' in line and not line.strip().startswith('//') and 'license/download' not in line:
                    if any(term in line for term in ['getItem', 'search', 'hash', 'pathname', 'href.includes', 'match', 'split']):
                        hits.append(f'{rel_path}:{idx}: {line.strip()}')
for h in hits:
    print(h)
" "$WEB_DIR")

if [ -n "$URL_TOKEN_HITS" ]; then
    echo "Violation: reading authentication token from URLSearchParams or location:"
    echo "$URL_TOKEN_HITS"
    VIOLATIONS=$((VIOLATIONS + $(echo "$URL_TOKEN_HITS" | wc -l)))
fi

if [ "$VIOLATIONS" -gt 0 ]; then
    echo "Total violations found: $VIOLATIONS"
    exit 1
else
    echo "XSS scan passed: 0 violations found."
    exit 0
fi
