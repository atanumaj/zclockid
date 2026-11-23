"""
api/db/connection.py: Centralized SQLite connection manager.
Provides get_db() context manager enforcing:
- WAL journal mode: PRAGMA journal_mode=WAL;
- Busy timeout: PRAGMA busy_timeout=5000;
- Foreign key constraints: PRAGMA foreign_keys=ON;
- Secure delete: PRAGMA secure_delete=ON;
- Row factory: sqlite3.Row
- Guarantees connection closure on exit.
"""

import os
import sqlite3
from pathlib import Path
from typing import Optional, Union


class DBConnectionContext:
    def __init__(self, db_path: Optional[Union[str, Path]] = None, timeout: float = 5.0):
        self._db_path = db_path
        self.timeout = timeout
        self._conn: Optional[sqlite3.Connection] = None
        self._closed: bool = False

    @property
    def db_path(self) -> Path:
        if self._db_path is not None:
            return Path(self._db_path)
        try:
            import api.core.config as config
            return getattr(config, "DB_PATH", Path("/var/lib/zclockid/zclockid.db"))
        except Exception:
            data_dir = os.environ.get("ZCLOCKID_DATA_DIR", "/var/lib/zclockid")
            return Path(data_dir) / "zclockid.db"

    def _get_conn(self) -> sqlite3.Connection:
        if self._closed:
            raise sqlite3.ProgrammingError("Cannot operate on a closed database.")
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, timeout=self.timeout)
            self._conn.row_factory = sqlite3.Row
            try:
                self._conn.execute("PRAGMA journal_mode=WAL;")
                self._conn.execute("PRAGMA busy_timeout=5000;")
                self._conn.execute("PRAGMA foreign_keys=ON;")
                self._conn.execute("PRAGMA secure_delete=ON;")
            except Exception:
                pass
        return self._conn

    def __enter__(self) -> sqlite3.Connection:
        return self._get_conn()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self._closed = True
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def backup(self, target, *args, **kwargs):
        real_target = target._get_conn() if isinstance(target, DBConnectionContext) else target
        return self._get_conn().backup(real_target, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._get_conn(), name)

    def __setattr__(self, name, value):
        if name.startswith("_") or name in ("timeout",):
            super().__setattr__(name, value)
        else:
            setattr(self._get_conn(), name, value)


def get_db(db_path: Optional[Union[str, Path]] = None, timeout: float = 5.0) -> DBConnectionContext:
    """Returns a context manager for SQLite database connection with WAL and security pragmas."""
    return DBConnectionContext(db_path=db_path, timeout=timeout)
