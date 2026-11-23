"""
ZclockID Registration Purge Service
Runs at startup and periodically (every 60s) under a file lock.
- Expires PENDING_OTP and cleans secrets for LOCKED rows past (otp_expires_at + 60s).
- Expires PENDING_APPROVAL older than registration_approval_ttl_days (with clock guard).
- Deletes terminal stubs (EXPIRED_*, LOCKED, ERROR_REREGISTER) older than 24 hours.
"""

import os
import time
import fcntl
import sqlite3
from api.db.connection import get_db
import logging
import threading
from pathlib import Path
from typing import Dict, Any, Optional

from api.core.config import DB_PATH, DATA_DIR
from api.services.system_service import log_audit

logger = logging.getLogger("zclockid.registration_purge")
PURGE_LOCK_FILE = DATA_DIR / "registration_purge.lock"


def get_purge_db_connection() -> sqlite3.Connection:
    conn = get_db(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA secure_delete=ON")
    return conn


def run_registration_purge(current_time: Optional[float] = None, force_clock_guard: bool = False) -> Dict[str, Any]:
    """
    Executes a single cycle of the registration purge job under file lock.
    Returns metrics on expired and pruned registrations.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(PURGE_LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        os.close(lock_fd)
        logger.debug("Registration purge job already running on another thread/process. Skipping.")
        return {"status": "skipped", "reason": "locked"}

    try:
        now = current_time if current_time is not None else time.time()
        conn = get_purge_db_connection()
        cursor = conn.cursor()

        # 1. Load settings
        cursor.execute("SELECT * FROM self_registration_settings WHERE id = 1")
        settings_row = cursor.fetchone()
        settings = dict(settings_row) if settings_row else {}

        ttl_days = int(settings.get("registration_approval_ttl_days", 7) or 7)
        ttl_days = max(1, min(90, ttl_days))

        expired_otp_count = 0
        locked_cleaned_count = 0
        expired_approval_count = 0
        stubs_deleted_count = 0
        clock_guard_tripped = False

        # 2. PENDING_OTP with now > otp_expires_at + 60 -> EXPIRED_OTP
        cursor.execute("""
            SELECT id, username FROM self_registrations
            WHERE status = 'PENDING_OTP' AND ? > (otp_expires_at + 60)
        """, (now,))
        otp_expired_rows = cursor.fetchall()
        for row in otp_expired_rows:
            cursor.execute("""
                UPDATE self_registrations
                SET status = 'EXPIRED_OTP', password_enc = NULL, otp_code = NULL, approved_at = ?
                WHERE id = ?
            """, (now, row["id"]))
            expired_otp_count += 1
        conn.commit()
        for row in otp_expired_rows:
            log_audit("REGISTRATION_OTP_EXPIRED", row["username"], "appliance", "EXPIRED", {"id": row["id"]})

        # LOCKED with now > (otp_expires_at or created_at) + 60 -> Keep LOCKED, password_enc & otp_code NULL
        cursor.execute("""
            SELECT id, username FROM self_registrations
            WHERE status = 'LOCKED' AND (password_enc IS NOT NULL OR otp_code IS NOT NULL)
            AND ? > (COALESCE(otp_expires_at, created_at) + 60)
        """, (now,))
        for row in cursor.fetchall():
            cursor.execute("""
                UPDATE self_registrations
                SET password_enc = NULL, otp_code = NULL
                WHERE id = ?
            """, (row["id"],))
            locked_cleaned_count += 1
        conn.commit()

        # 3. PENDING_APPROVAL older than registration_approval_ttl_days
        approval_cutoff = now - (ttl_days * 86400)
        cursor.execute("SELECT id, username, COALESCE(otp_verified_at, created_at) as effective_at FROM self_registrations WHERE status = 'PENDING_APPROVAL'")
        all_pending = cursor.fetchall()
        total_pending = len(all_pending)

        candidates = [row for row in all_pending if (row["effective_at"] or 0) < approval_cutoff]
        cand_count = len(candidates)

        # Clock guard evaluation:
        # If one run would expire more than 20% of pending rows (or more than 10 rows when there are fewer than 50), skip it!
        should_trip = False
        if cand_count > 0:
            if total_pending < 50:
                if cand_count > 10:
                    should_trip = True
            else:
                if cand_count > (0.20 * total_pending):
                    should_trip = True

        if should_trip and not force_clock_guard:
            clock_guard_tripped = True
            cursor.execute("""
                UPDATE self_registration_settings
                SET approval_purge_tripped = 1,
                    approval_purge_pending_count = ?,
                    approval_purge_detected_at = ?
                WHERE id = 1
            """, (cand_count, now))
            conn.commit()
            log_audit("REGISTRATION_APPROVAL_CLOCK_GUARD_TRIPPED", "system", "appliance", "WARNING", {
                "candidates_count": cand_count,
                "total_pending": total_pending,
                "ttl_days": ttl_days
            })
            logger.warning(f"Registration approval purge clock guard tripped! {cand_count}/{total_pending} rows pending expiration.")
        else:
            # Clear tripped banner state
            cursor.execute("""
                UPDATE self_registration_settings
                SET approval_purge_tripped = 0,
                    approval_purge_pending_count = 0,
                    approval_purge_detected_at = 0
                WHERE id = 1
            """)
            for row in candidates:
                cursor.execute("""
                    UPDATE self_registrations
                    SET status = 'EXPIRED_APPROVAL', password_enc = NULL, approved_at = ?
                    WHERE id = ?
                """, (now, row["id"]))
                expired_approval_count += 1
            conn.commit()
            for row in candidates:
                log_audit("REGISTRATION_APPROVAL_EXPIRED", row["username"], "appliance", "EXPIRED", {"id": row["id"]})

        # 4. Stubs (EXPIRED_*, LOCKED, ERROR_REREGISTER) older than 24h -> DELETE
        stubs_cutoff = now - 86400
        cursor.execute("""
            SELECT id FROM self_registrations
            WHERE status IN ('EXPIRED_OTP', 'EXPIRED_APPROVAL', 'LOCKED', 'ERROR_REREGISTER')
            AND COALESCE(approved_at, otp_expires_at, created_at) < ?
        """, (stubs_cutoff,))
        stubs_to_del = cursor.fetchall()
        for row in stubs_to_del:
            cursor.execute("DELETE FROM self_registrations WHERE id = ?", (row["id"],))
            stubs_deleted_count += 1

        conn.commit()
        conn.close()

        return {
            "status": "success",
            "expired_otp": expired_otp_count,
            "locked_cleaned": locked_cleaned_count,
            "expired_approval": expired_approval_count,
            "stubs_deleted": stubs_deleted_count,
            "clock_guard_tripped": clock_guard_tripped
        }
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except Exception:
            pass
        os.close(lock_fd)


def _purge_worker_loop():
    logger.info("Registration background purge worker started (interval: 60s).")
    while True:
        try:
            run_registration_purge()
        except Exception as e:
            logger.error(f"Error in registration purge cycle: {e}")
        time.sleep(60)


_worker_started = False
_worker_lock = threading.Lock()

def start_registration_purge_worker():
    """Starts the background 60s registration purge thread."""
    global _worker_started
    with _worker_lock:
        if not _worker_started:
            t = threading.Thread(target=_purge_worker_loop, daemon=True, name="RegistrationPurgeWorker")
            t.start()
            _worker_started = True
