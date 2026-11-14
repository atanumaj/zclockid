"""
Pytest configuration and global environment fixtures for ZclockID tests.
Ensures non-root test runs (such as local macOS dev environments) use an isolated temporary updates directory.
"""

import os
import tempfile
import pytest

_TEST_UPDATES_DIR = os.path.join(tempfile.gettempdir(), "zclockid-test-updates")
os.makedirs(_TEST_UPDATES_DIR, mode=0o700, exist_ok=True)
os.environ.setdefault("ZCLOCKID_UPDATES_DIR", _TEST_UPDATES_DIR)
