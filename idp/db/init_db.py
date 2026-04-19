import os
import sqlite3
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

# Load .env from the project root (two levels above db/)
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))

# Build the absolute path from DB_FILE: always stored in db/data/
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', os.getenv('DB_FILE', 'data.db'))

# Default user credentials loaded from .env
DEFAULT_USER = os.getenv('DEFAULT_USER', 'admin')
DEFAULT_PASSWORD = os.getenv('DEFAULT_PASSWORD', 'admin123')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # users: stripped down to only what's needed
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            mfa_secret    TEXT
        )
    ''')

    # user_logs: one row per successful login
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            ip        TEXT    NOT NULL,
            location  TEXT    NOT NULL DEFAULT 'Unknown',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # ip_logs: all IP-level events — FAILED, BLOCKED, and SUCCESS
    #   blocked_until  — only set on BLOCKED rows; the future datetime when the block lifts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_logs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ip            TEXT     NOT NULL,
            location      TEXT     NOT NULL DEFAULT 'Unknown',
            timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
            username      TEXT,
            status        TEXT     NOT NULL CHECK(status IN ('FAILED', 'BLOCKED', 'SUCCESS')),
            blocked_until DATETIME
        )
    ''')

    p_hash = generate_password_hash(DEFAULT_PASSWORD)
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (DEFAULT_USER, p_hash)
        )
    except Exception:
        pass

    conn.commit()
    conn.close()
    print("[DB] Database initialized.")

if __name__ == '__main__':
    init_db()
