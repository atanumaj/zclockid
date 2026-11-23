"""
tests/test_postinst_migration.py: Verifies postinst APT source migration and updater fetches.
Verifies that:
1. postinst on a box with old sources list (/etc/apt/sources.list.d/zclockid.sources with .../master/apt-repo)
   rewrites the URI to .../gh-pages/apt-repo idempotently while preserving keyring.
2. The system updater fetches the official manifest, .deb package, and detached .deb.sig
   from the new gh-pages location successfully with valid cryptographic signature.
"""

import os
import sys
import re
import json
import subprocess
from pathlib import Path
import pytest
import requests

from api.core.config import OFFICIAL_MANIFEST_URL


def test_postinst_rewrites_sources_to_gh_pages(tmp_path):
    """
    Test Item 1b & 2: Extract step 8 directly from package/debian/postinst
    (no copied snippet) and execute that against simulated /etc/apt/sources.list.d/ files.
    """
    repo_root = Path(__file__).resolve().parent.parent
    postinst_file = repo_root / "package" / "debian" / "postinst"
    assert postinst_file.exists(), f"postinst file not found at {postinst_file}"

    # Extract Step 8 block from postinst
    postinst_text = postinst_file.read_text(encoding="utf-8")
    match = re.search(r"(# 8\. Migrate APT source.*?)(?=\n\s*# \d+\.|\nesac|\Z)", postinst_text, re.DOTALL)
    assert match is not None, "Step 8 could not be found in package/debian/postinst"
    step8_code = match.group(1).strip()
    assert "gh-pages" in step8_code, f"Step 8 does not reference gh-pages: {step8_code}"

    sources_dir = tmp_path / "sources.list.d"
    sources_dir.mkdir(parents=True, exist_ok=True)
    sources_file = sources_dir / "zclockid.sources"
    list_file = sources_dir / "zclockid.list"

    # Seed with the legacy master URI
    old_sources_content = (
        "Types: deb\n"
        "URIs: https://raw.githubusercontent.com/atanumaj/zclockid/master/apt-repo\n"
        "Suites: stable\n"
        "Components: main\n"
        "Signed-By: /usr/share/keyrings/zclockid-archive-keyring.gpg\n"
    )
    old_list_content = (
        "deb [signed-by=/usr/share/keyrings/zclockid-archive-keyring.gpg] "
        "https://raw.githubusercontent.com/atanumaj/zclockid/master/apt-repo stable main\n"
    )

    sources_file.write_text(old_sources_content)
    list_file.write_text(old_list_content)

    # In Step 8 from postinst, rewrite the hardcoded system path /etc/apt/sources.list.d to our tmp_path sources_dir
    adapted_script = step8_code.replace("/etc/apt/sources.list.d", str(sources_dir))

    # Provide gnu-sed on PATH as sed on macOS if present, or adapt sed to BSD sed if needed
    env = os.environ.copy()
    gnubin_sed = Path("/opt/homebrew/opt/gnu-sed/libexec/gnubin")
    if gnubin_sed.exists():
        env["PATH"] = f"{gnubin_sed}:{env['PATH']}"
    elif sys.platform == "darwin":
        # If gnu-sed not available on Darwin, handle sed -i '' compatibility
        adapted_script = adapted_script.replace("sed -i 's|", "sed -i '' 's|")

    # Run extracted step 8 first time
    proc1 = subprocess.run(["sh", "-c", adapted_script], capture_output=True, text=True, env=env)
    assert proc1.returncode == 0, f"Postinst extracted step 8 failed: {proc1.stderr}"

    new_sources = sources_file.read_text()
    new_list = list_file.read_text()

    assert "raw.githubusercontent.com/atanumaj/zclockid/gh-pages/apt-repo" in new_sources
    assert "master" not in new_sources
    assert "Signed-By: /usr/share/keyrings/zclockid-archive-keyring.gpg" in new_sources

    assert "raw.githubusercontent.com/atanumaj/zclockid/gh-pages/apt-repo" in new_list
    assert "master" not in new_list
    assert "[signed-by=/usr/share/keyrings/zclockid-archive-keyring.gpg]" in new_list

    # Run extracted step 8 second time (idempotency check)
    proc2 = subprocess.run(["sh", "-c", adapted_script], capture_output=True, text=True, env=env)
    assert proc2.returncode == 0
    assert sources_file.read_text() == new_sources
    assert list_file.read_text() == new_list


def test_updater_fetches_manifest_and_packages_from_gh_pages(tmp_path):
    """
    Test Item 1b: Updater fetches manifest, .deb, and .sig from the new location (gh-pages)
    and verifies GPG signature integrity.
    """
    assert "gh-pages" in OFFICIAL_MANIFEST_URL

    res = requests.get(OFFICIAL_MANIFEST_URL, timeout=10)
    assert res.status_code == 200, f"Failed to fetch manifest from {OFFICIAL_MANIFEST_URL}"
    manifest = res.json()

    assert manifest["version"] == "1.5.4"
    assert "gh-pages" in manifest["download_url"]

    # Verify download_url is directly reachable
    deb_res = requests.head(manifest["download_url"], timeout=10)
    assert deb_res.status_code == 200, f"Failed to reach {manifest['download_url']}: status {deb_res.status_code}"

    # Verify detached signature is directly reachable
    sig_url = f"{manifest['download_url']}.sig"
    sig_res = requests.head(sig_url, timeout=10)
    assert sig_res.status_code == 200, f"Failed to reach signature at {sig_url}: status {sig_res.status_code}"

    # Verify cryptographic signature using official keyring
    repo_root = Path(__file__).resolve().parent.parent
    keyring_file = repo_root / "package" / "keyrings" / "zclockid-archive-keyring.gpg"
    assert keyring_file.exists()

    # Download deb and sig for verification
    deb_path = tmp_path / "downloaded.deb"
    sig_path = tmp_path / "downloaded.deb.sig"

    deb_path.write_bytes(requests.get(manifest["download_url"], timeout=30).content)
    sig_path.write_bytes(requests.get(sig_url, timeout=10).content)

    gpg_res = subprocess.run(
        ["gpgv", "--keyring", str(keyring_file), str(sig_path), str(deb_path)],
        capture_output=True, text=True
    )
    assert gpg_res.returncode == 0, f"GPG verification failed: {gpg_res.stderr}\n{gpg_res.stdout}"
    assert "Good signature" in (gpg_res.stderr + gpg_res.stdout)
