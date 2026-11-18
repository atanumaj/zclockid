"""
Pytest configuration and global environment fixtures for ZclockID tests.
Ensures non-root test runs (such as local macOS dev environments) use isolated temporary directories
and guarantees no test touches or modifies the host's real /etc/zclockid directory.
"""

import os
import tempfile
from pathlib import Path
import pytest

_TEST_UPDATES_DIR = os.path.join(tempfile.gettempdir(), "zclockid-test-updates")
os.makedirs(_TEST_UPDATES_DIR, mode=0o700, exist_ok=True)
os.environ.setdefault("ZCLOCKID_UPDATES_DIR", _TEST_UPDATES_DIR)

_TEST_REG_KEYS_DIR = os.path.join(tempfile.gettempdir(), "zclockid-test-reg-keys")
os.makedirs(_TEST_REG_KEYS_DIR, mode=0o700, exist_ok=True)
os.environ.setdefault("ZCLOCKID_REG_KEYS_DIR", _TEST_REG_KEYS_DIR)

_TEST_CONFIG_DIR = os.path.join(tempfile.gettempdir(), "zclockid-test-config")
os.makedirs(_TEST_CONFIG_DIR, mode=0o700, exist_ok=True)
os.environ.setdefault("ZCLOCKID_CONFIG_DIR", _TEST_CONFIG_DIR)

_TEST_DATA_DIR = os.path.join(tempfile.gettempdir(), "zclockid-test-data")
os.makedirs(_TEST_DATA_DIR, mode=0o700, exist_ok=True)
os.environ.setdefault("ZCLOCKID_DATA_DIR", _TEST_DATA_DIR)


def _snapshot_etc_zclockid():
    p = Path("/etc/zclockid")
    if not p.exists():
        return None
    files = {}
    try:
        for root, _, fnames in os.walk(str(p)):
            for fn in fnames:
                fp = os.path.join(root, fn)
                try:
                    st = os.stat(fp)
                    files[fp] = (st.st_mtime_ns, st.st_size)
                except Exception:
                    pass
    except Exception:
        pass
    return files


@pytest.fixture(autouse=True)
def guard_etc_zclockid():
    """Fails the test run if any test creates or modifies anything under the real /etc/zclockid."""
    initial = _snapshot_etc_zclockid()
    yield
    current = _snapshot_etc_zclockid()
    if initial is None:
        if Path("/etc/zclockid").exists():
            pytest.fail("Test created /etc/zclockid! Tests must remain isolated in temporary directories.")
    else:
        if current != initial:
            pytest.fail("Test modified contents of /etc/zclockid! Tests must remain isolated.")


_KNOWN_TEST_PASSWORDS = {
    "AdminP@ss2026!",
    "SecureP@ssw0rd2026!",
    "Password123!",
    "MockPass123!",
    "NewSecretPass123!",
    "VeryConfidentialADPassword2026!",
    "DomainP@ssw0rd2026!"
}


@pytest.fixture(autouse=True)
def guard_no_cli_secrets(monkeypatch):
    """
    Fails any test if subprocess.run or run_cmd is invoked with arguments containing
    --password=, --newpassword=, --adminpass=, or any known test passwords.
    Guarantees secrets are kept off the command line across the whole test suite.
    """
    import subprocess
    import api.services.system_service as sys_svc

    orig_subproc_run = subprocess.run
    orig_run_cmd = sys_svc.run_cmd

    def _check_args(args):
        if not args:
            return
        arg_list = list(args if isinstance(args, (list, tuple)) else str(args).split())
        if arg_list and Path(str(arg_list[0])).name in ("grep", "rg", "git"):
            return
        for a in arg_list:
            a_str = str(a)
            if "--password=" in a_str or "--newpassword=" in a_str or "--adminpass=" in a_str:
                pytest.fail(f"Secret leakage detected in CLI arguments: {a_str}")
            for kw in _KNOWN_TEST_PASSWORDS:
                if kw in a_str:
                    pytest.fail(f"Known test password leaked in CLI argument: {a_str}")

    def safe_subproc_run(*args, **kwargs):
        cmd = args[0] if args else kwargs.get("args")
        _check_args(cmd)
        return orig_subproc_run(*args, **kwargs)

    def safe_run_cmd(cmd, *args, **kwargs):
        _check_args(cmd)
        return orig_run_cmd(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", safe_subproc_run)
    monkeypatch.setattr(sys_svc, "run_cmd", safe_run_cmd)
    yield
