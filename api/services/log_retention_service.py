import json
import sqlite3
import time
from typing import Dict, Any

from api.core.config import DB_PATH

DEFAULT_RETENTION_SETTINGS: Dict[str, Any] = {
    "audit_retention_days": 180,
    "audit_max_entries": 50000,
    "audit_ui_fetch_limit": 500,
    "self_service_retention_days": 180,
    "self_service_max_entries": 10000,
    "self_service_ui_fetch_limit": 500,
    "live_log_default_lines": 100,
    "live_log_max_lines": 1000,
    "radius_retention_days": 180,
    "radius_max_entries": 50000,
    "radius_ui_fetch_limit": 200,
    "auto_prune_enabled": 1,
    "last_pruned_at": 0.0,
    "last_pruned_summary": "{}",
}


def _ensure_table(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS log_retention_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            audit_retention_days INTEGER DEFAULT 180,
            audit_max_entries INTEGER DEFAULT 50000,
            audit_ui_fetch_limit INTEGER DEFAULT 500,
            self_service_retention_days INTEGER DEFAULT 180,
            self_service_max_entries INTEGER DEFAULT 10000,
            self_service_ui_fetch_limit INTEGER DEFAULT 500,
            live_log_default_lines INTEGER DEFAULT 100,
            live_log_max_lines INTEGER DEFAULT 1000,
            radius_retention_days INTEGER DEFAULT 180,
            radius_max_entries INTEGER DEFAULT 50000,
            radius_ui_fetch_limit INTEGER DEFAULT 200,
            auto_prune_enabled INTEGER DEFAULT 1,
            last_pruned_at REAL DEFAULT 0,
            last_pruned_summary TEXT DEFAULT '{}',
            updated_at REAL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM log_retention_settings WHERE id = 1")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO log_retention_settings (
                id, audit_retention_days, audit_max_entries, audit_ui_fetch_limit,
                self_service_retention_days, self_service_max_entries, self_service_ui_fetch_limit,
                live_log_default_lines, live_log_max_lines,
                radius_retention_days, radius_max_entries, radius_ui_fetch_limit,
                auto_prune_enabled, last_pruned_at, last_pruned_summary, updated_at
            ) VALUES (1, 180, 50000, 500, 180, 10000, 500, 100, 1000, 180, 50000, 200, 1, 0, '{}', ?)
        """, (time.time(),))
        conn.commit()


def get_log_retention_settings() -> Dict[str, Any]:
    """Returns current log retention and query limit settings with safe defaults."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        _ensure_table(conn)
        row = conn.execute("SELECT * FROM log_retention_settings WHERE id = 1").fetchone()
        conn.close()
        if row:
            data = dict(DEFAULT_RETENTION_SETTINGS)
            data.update(dict(row))
            return data
    except Exception:
        pass
    return dict(DEFAULT_RETENTION_SETTINGS)


def update_log_retention_settings(updates: Dict[str, Any]) -> Dict[str, Any]:
    """Persists updated log retention and query limit settings."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _ensure_table(conn)

    allowed_fields = [
        "audit_retention_days",
        "audit_max_entries",
        "audit_ui_fetch_limit",
        "self_service_retention_days",
        "self_service_max_entries",
        "self_service_ui_fetch_limit",
        "live_log_default_lines",
        "live_log_max_lines",
        "radius_retention_days",
        "radius_max_entries",
        "radius_ui_fetch_limit",
        "auto_prune_enabled",
    ]
    set_clauses = []
    values = []
    for field in allowed_fields:
        if field in updates and updates[field] is not None:
            set_clauses.append(f"{field} = ?")
            values.append(int(updates[field]))

    if set_clauses:
        set_clauses.append("updated_at = ?")
        values.append(time.time())
        conn.execute(
            f"UPDATE log_retention_settings SET {', '.join(set_clauses)} WHERE id = 1",
            tuple(values),
        )
        conn.commit()

    row = conn.execute("SELECT * FROM log_retention_settings WHERE id = 1").fetchone()
    conn.close()
    data = dict(DEFAULT_RETENTION_SETTINGS)
    if row:
        data.update(dict(row))
    return data


def get_log_table_counts() -> Dict[str, int]:
    """Returns current row counts across all logging and reporting tables."""
    tables = [
        "audit_events",
        "self_registrations",
        "self_service_password_logs",
        "radius_accounting",
        "failed_login_attempts",
    ]
    counts: Dict[str, int] = {t: 0 for t in tables}
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        for t in tables:
            try:
                cur.execute(f"SELECT COUNT(*) FROM {t}")
                counts[t] = int(cur.fetchone()[0])
            except Exception:
                counts[t] = 0
        conn.close()
    except Exception:
        pass
    return counts


def _prune_table(
    cur: sqlite3.Cursor,
    table: str,
    ts_col: str,
    retention_days: int,
    max_entries: int,
    now_ts: float,
    where_guard: str = "1=1",
) -> int:
    """Deletes expired rows by age and/or excess rows beyond max_entries."""
    deleted = 0
    if retention_days and retention_days > 0:
        cutoff = now_ts - (retention_days * 86400)
        cur.execute(f"DELETE FROM {table} WHERE ({where_guard}) AND {ts_col} < ?", (cutoff,))
        deleted += cur.rowcount or 0

    if max_entries and max_entries > 0:
        cur.execute(
            f"""
            DELETE FROM {table}
            WHERE ({where_guard})
              AND id NOT IN (
                  SELECT id FROM {table}
                  ORDER BY {ts_col} DESC, id DESC
                  LIMIT ?
              )
            """,
            (max_entries,),
        )
        deleted += cur.rowcount or 0
    return deleted


def prune_logs_by_policy(force: bool = False) -> Dict[str, Any]:
    """Enforces configured retention_days and max_entries across all log tables."""
    settings = get_log_retention_settings()
    if not force and not settings.get("auto_prune_enabled", 1):
        return {"skipped": True, "reason": "auto_prune_disabled", "deleted": {}}

    now_ts = time.time()
    deleted: Dict[str, int] = {}

    conn = sqlite3.connect(DB_PATH)
    _ensure_table(conn)
    cur = conn.cursor()

    try:
        deleted["audit_events"] = _prune_table(
            cur,
            "audit_events",
            "timestamp",
            int(settings.get("audit_retention_days", 180)),
            int(settings.get("audit_max_entries", 50000)),
            now_ts,
        )
        deleted["failed_login_attempts"] = _prune_table(
            cur,
            "failed_login_attempts",
            "timestamp",
            int(settings.get("audit_retention_days", 180)),
            int(settings.get("audit_max_entries", 50000)),
            now_ts,
        )
        deleted["self_registrations"] = _prune_table(
            cur,
            "self_registrations",
            "created_at",
            int(settings.get("self_service_retention_days", 180)),
            int(settings.get("self_service_max_entries", 10000)),
            now_ts,
            where_guard="status IN ('VERIFIED_AUTO_PROVISIONED', 'APPROVED', 'REJECTED', 'PENDING_OTP')",
        )
        deleted["self_service_password_logs"] = _prune_table(
            cur,
            "self_service_password_logs",
            "created_at",
            int(settings.get("self_service_retention_days", 180)),
            int(settings.get("self_service_max_entries", 10000)),
            now_ts,
        )
        deleted["radius_accounting"] = _prune_table(
            cur,
            "radius_accounting",
            "last_update",
            int(settings.get("radius_retention_days", 180)),
            int(settings.get("radius_max_entries", 50000)),
            now_ts,
        )

        summary_json = json.dumps(deleted)
        cur.execute(
            "UPDATE log_retention_settings SET last_pruned_at = ?, last_pruned_summary = ? WHERE id = 1",
            (now_ts, summary_json),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "skipped": False,
        "pruned_at": now_ts,
        "deleted": deleted,
        "total_deleted": sum(deleted.values()),
        "counts": get_log_table_counts(),
    }
