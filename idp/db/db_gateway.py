import os
import sqlite3
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load .env from the project root (two levels above db/)
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))

MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', 3))
LOCK_TIME    = int(os.getenv('LOCK_TIME', 15))

# Build the absolute path from DB_FILE: always stored in db/data/
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', os.getenv('DB_FILE', 'data.db'))


def get_db() -> sqlite3.Connection:
    """Return a new SQLite connection."""
    return sqlite3.connect(DB_PATH)


# ──────────────────────────────────────────────────────────────
# READ helpers (open their own short-lived connections)
# ──────────────────────────────────────────────────────────────

def check_ip_blocked(ip: str) -> tuple[bool, int]:
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT blocked_until FROM ip_logs '
        'WHERE ip = ? AND status = "BLOCKED" AND blocked_until > datetime("now") '
        'ORDER BY blocked_until DESC LIMIT 1',
        (ip,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False, 0

    blocked_until = datetime.fromisoformat(row[0])
    now           = datetime.now(timezone.utc).replace(tzinfo=None)
    remaining     = max(0, int((blocked_until - now).total_seconds()))
    return True, remaining


def get_next_block_duration(ip: str) -> int:
    conn   = get_db()
    cursor = conn.cursor()

    cursor.execute(
        'SELECT timestamp, blocked_until FROM ip_logs '
        'WHERE ip = ? AND status = "BLOCKED" '
        'ORDER BY rowid DESC LIMIT 1',
        (ip,)
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return LOCK_TIME

    block_ts_str, blocked_until_str = row

    block_ts = datetime.fromisoformat(block_ts_str)
    blocked_until = datetime.fromisoformat(blocked_until_str)
    prev_duration = max(LOCK_TIME, int((blocked_until - block_ts).total_seconds()))

    cursor.execute(
        'SELECT COUNT(*) FROM ip_logs '
        'WHERE ip = ? AND status = "SUCCESS" AND timestamp > ?',
        (ip, blocked_until_str)
    )
    success_after_block = cursor.fetchone()[0]
    conn.close()

    return LOCK_TIME if success_after_block > 0 else prev_duration * 2


def get_recent_failure_count(cursor: sqlite3.Cursor, ip: str) -> int:
    cursor.execute(
        'SELECT timestamp FROM ip_logs '
        'WHERE ip = ? AND status = "SUCCESS" '
        'ORDER BY rowid DESC LIMIT 1',
        (ip,)
    )
    row = cursor.fetchone()

    if row:
        cursor.execute(
            'SELECT COUNT(*) FROM ip_logs '
            'WHERE ip = ? AND status = "FAILED" AND timestamp > ?',
            (ip, row[0])
        )
    else:
        cursor.execute(
            'SELECT COUNT(*) FROM ip_logs WHERE ip = ? AND status = "FAILED"',
            (ip,)
        )

    return cursor.fetchone()[0]


# ──────────────────────────────────────────────────────────────
# WRITE helpers (take an open cursor — caller owns commit/close)
# ──────────────────────────────────────────────────────────────

def insert_failed_attempt(cursor: sqlite3.Cursor,ip: str,location: str,username: str | None) -> None:
    cursor.execute(
        'INSERT INTO ip_logs (ip, location, username, status) VALUES (?, ?, ?, "FAILED")',
        (ip, location, username)
    )


def insert_blocked(cursor: sqlite3.Cursor,ip: str,location: str,username: str | None,block_duration: int) -> None:
    cursor.execute(
        'INSERT INTO ip_logs (ip, location, username, status, blocked_until) '
        'VALUES (?, ?, ?, "BLOCKED", datetime("now", ?))',
        (ip, location, username, f'+{block_duration} seconds')
    )


def insert_success_data(cursor: sqlite3.Cursor,ip: str,user_id: int,location: str,username: str) -> None:
    cursor.execute(
        'INSERT INTO ip_logs (ip, location, username, status) VALUES (?, ?, ?, "SUCCESS")',
        (ip, location, username)
    )
    cursor.execute(
        'INSERT INTO user_logs (user_id, ip, location) VALUES (?, ?, ?)',
        (user_id, ip, location)
    )
    