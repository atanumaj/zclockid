"""
tests/test_cli_secrets_isolation.py: Automated tests for v1.4.9 secret isolation.
Verifies that:
1. No call sites in api/ pass --password=, --newpassword=, or --adminpass= on the command line.
2. User and group operations execute in-process via SamDB without CLI arguments.
3. samba-tool authenticated commands use temporary 0600 auth files (-A<file>) unlinked in finally.
4. The test fixture guard prevents any command line password leakage.
"""

import os
import shutil
import subprocess
import pytest
from pathlib import Path
from api.services.samdb_service import (
    samdb_newuser,
    samdb_setpassword,
    samdb_setexpiry,
    samdb_enable_account,
    samdb_disable_account,
    samdb_deleteuser,
    samdb_newgroup,
    samdb_deletegroup,
    samdb_add_group_member,
    samdb_remove_group_member,
    temporary_auth_file,
    run_samba_tool_authenticated,
    get_samdb
)
from api.services.system_service import run_cmd


def test_grep_no_password_arguments_in_api():
    """CI Check: grep -rn -- '--password=' api/ must return 0 results."""
    repo_root = Path(__file__).resolve().parent.parent
    api_dir = repo_root / "api"
    assert api_dir.exists(), f"api directory not found at {api_dir}"

    result = subprocess.run(
        ["grep", "-rn", "--exclude=*.pyc", "--", "--password=", str(api_dir)],
        capture_output=True,
        text=True
    )
    # Return code 1 means grep found 0 matches
    assert result.returncode == 1, f"Found --password= in api/: {result.stdout}"
    assert result.stdout.strip() == ""


def test_grep_no_newpassword_arguments_in_api():
    """Grep check: grep -rn -- '--newpassword=' api/ must return 0 results."""
    repo_root = Path(__file__).resolve().parent.parent
    api_dir = repo_root / "api"

    result = subprocess.run(
        ["grep", "-rn", "--exclude=*.pyc", "--", "--newpassword=", str(api_dir)],
        capture_output=True,
        text=True
    )
    assert result.returncode == 1, f"Found --newpassword= in api/: {result.stdout}"
    assert result.stdout.strip() == ""


def test_grep_no_adminpass_arguments_in_api():
    """Grep check: grep -rn -- '--adminpass=' api/ must return 0 results."""
    repo_root = Path(__file__).resolve().parent.parent
    api_dir = repo_root / "api"

    result = subprocess.run(
        ["grep", "-rn", "--exclude=*.pyc", "--", "--adminpass=", str(api_dir)],
        capture_output=True,
        text=True
    )
    assert result.returncode == 1, f"Found --adminpass= in api/: {result.stdout}"
    assert result.stdout.strip() == ""


def test_generic_no_zclock_pass_defaults():
    """CI Check: Ensure no environ lookup for appliance password provides a fallback default."""
    repo_root = Path(__file__).resolve().parent.parent
    pattern = r'os\.(environ\.get|getenv)\(["\']ZCLOCK_PASS["\'],\s*[^)]+\)'
    this_file = Path(__file__).resolve()
    for folder in ["tests", "scripts", "api", ".github"]:
        target_path = repo_root / folder
        if not target_path.exists():
            continue
        result = subprocess.run(
            ["grep", "-rnE", "--exclude=*.pyc", "--exclude-dir=__pycache__", pattern, str(target_path)],
            capture_output=True,
            text=True
        )
        # Filter out self
        lines = [line for line in result.stdout.strip().splitlines() if line and str(this_file) not in line]
        assert len(lines) == 0, f"Found ZCLOCK_PASS with default in {folder}/:\n" + "\n".join(lines)


def test_gitleaks_audit_working_tree():
    """CI Check: Ensure gitleaks detect reports zero unallowlisted leaks."""
    gitleaks_bin = shutil.which("gitleaks") or "/opt/homebrew/bin/gitleaks"
    if not Path(gitleaks_bin).exists():
        pytest.skip("gitleaks binary not found on local system")
    repo_root = Path(__file__).resolve().parent.parent
    config_file = repo_root / ".gitleaks.toml"
    assert config_file.exists(), ".gitleaks.toml configuration is required"
    cmd = [gitleaks_bin, "detect", "--source", str(repo_root), "--config", str(config_file), "--redact"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Gitleaks detected leaks:\n{result.stdout}\n{result.stderr}"


def test_temporary_auth_file_mode_and_cleanup():
    """Ensures temporary_auth_file creates a 0600 file and unlinks it in finally."""
    created_path = None
    with temporary_auth_file(username="testadmin", password="TestSecretPassword!") as authfile:
        created_path = Path(authfile)
        assert created_path.exists(), "Auth file should exist inside context"
        stat = created_path.stat()
        assert (stat.st_mode & 0o777) == 0o600, f"Auth file mode must be 0600, got {oct(stat.st_mode)}"
        content = created_path.read_text()
        assert "username = testadmin" in content
        assert "password = TestSecretPassword!" in content

    assert not created_path.exists(), "Auth file must be unlinked immediately upon exit"


def test_samdb_in_process_user_and_group_lifecycle():
    """Tests all in-process SamDB user and group operations without CLI subprocess invocation."""
    db = get_samdb()

    # User lifecycle
    samdb_newuser(
        username="secuser1",
        password="MySecretP@ss2026!",
        given_name="Sec",
        surname="User",
        email="sec@example.com",
        department="Security"
    )
    samdb_setpassword("secuser1", "UpdatedP@ss2026!")
    samdb_setexpiry("secuser1", noexpiry=True)
    samdb_disable_account("secuser1")
    samdb_enable_account("secuser1")

    # Group lifecycle
    samdb_newgroup("SecGroup1", description="Security Test Group")
    samdb_add_group_member("SecGroup1", "secuser1")
    samdb_remove_group_member("SecGroup1", "secuser1")
    samdb_deletegroup("SecGroup1")
    samdb_deleteuser("secuser1")


def test_guard_fixture_blocks_forbidden_cli_arguments():
    """Verifies that our conftest guard fixture detects and blocks forbidden password CLI flags."""
    with pytest.raises(pytest.fail.Exception, match="Secret leakage detected in CLI arguments"):
        run_cmd(["echo", "--password=SuperSecret"])

    with pytest.raises(pytest.fail.Exception, match="Secret leakage detected in CLI arguments"):
        run_cmd(["echo", "--newpassword=SuperSecret"])

    with pytest.raises(pytest.fail.Exception, match="Known test password leaked in CLI argument"):
        run_cmd(["echo", "AdminP@ss2026!"])
