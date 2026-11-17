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
