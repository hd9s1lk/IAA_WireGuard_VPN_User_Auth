import os
import sqlite3
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))

MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', 3))
LOCK_TIME    = int(os.getenv('LOCK_TIME', 15))

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', os.getenv('DB_FILE', 'data.db'))


def get_db() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def check_ip_blocked(ip: str) -> tuple[bool, int]:
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT blocked_until FROM ips_blacklist '
        'WHERE ip = ? AND status = "BLOCKED" AND blocked_until > datetime("now")',
        (ip,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False, 0

    blocked_until = datetime.fromisoformat(row[0])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    remaining = max(0, int((blocked_until - now).total_seconds()))
    return True, remaining


def get_next_block_duration(ip: str) -> int:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT last_block_duration FROM ips_blacklist WHERE ip = ?',
        (ip,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row or row[0] is None:
        return LOCK_TIME

    return row[0] * 2


def get_recent_failure_count(cursor: sqlite3.Cursor, ip: str) -> int:
    cursor.execute(
        'SELECT attempt_count FROM ips_blacklist WHERE ip = ?',
        (ip,)
    )
    row = cursor.fetchone()
    return row[0] if row else 0


def insert_failed_attempt(cursor: sqlite3.Cursor, ip: str, location: str, username: str | None) -> None:
    cursor.execute(
        '''
        INSERT INTO ips_blacklist (ip, location, username, status, attempt_count)
        VALUES (?, ?, ?, "FAILED", 1)
        ON CONFLICT(ip) DO UPDATE SET
            attempt_count = attempt_count + 1,
            username      = excluded.username,
            location      = excluded.location,
            timestamp     = CURRENT_TIMESTAMP,
            status        = "FAILED"
        ''',
        (ip, location, username)
    )


def insert_blocked(cursor: sqlite3.Cursor, ip: str, location: str, username: str | None, block_duration: int) -> None:

    cursor.execute(
        '''
        UPDATE ips_blacklist SET
            status              = "BLOCKED",
            blocked_until       = datetime("now", ?),
            last_block_duration = ?,
            username            = ?,
            location            = ?,
            timestamp           = CURRENT_TIMESTAMP
        WHERE ip = ?
        ''',
        (f'+{block_duration} seconds', block_duration, username, location, ip)
    )


def insert_success_data(cursor: sqlite3.Cursor, ip: str, user_id: int, location: str, username: str, city: str = None, rba_score: int = 0) -> None:
    cursor.execute(
        'DELETE FROM ips_blacklist WHERE ip = ?',
        (ip,)
    )
    cursor.execute(
        'INSERT INTO user_logs (user_id, ip, location, city, rba_score) VALUES (?, ?, ?, ?, ?)',
        (user_id, ip, location, city, rba_score)
    )
