import os
import sqlite3
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', os.getenv('DB_FILE', 'data.db'))

DEFAULT_USER = os.getenv('DEFAULT_USER', 'admin')
DEFAULT_PASSWORD = os.getenv('DEFAULT_PASSWORD', 'admin123')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            mfa_secret    TEXT,
            mfa_enabled   INTEGER NOT NULL DEFAULT 0
        )
    ''')

    cursor.execute('PRAGMA table_info(users)')
    existing_columns = [row[1] for row in cursor.fetchall()]
    if 'mfa_enabled' not in existing_columns:
        cursor.execute('ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            ip        TEXT    NOT NULL,
            location  TEXT    NOT NULL DEFAULT 'Unknown',
            city      TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            rba_score INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('PRAGMA table_info(user_logs)')
    existing_columns = [row[1] for row in cursor.fetchall()]
    if 'city' not in existing_columns:
        cursor.execute('ALTER TABLE user_logs ADD COLUMN city TEXT')
    if 'rba_score' not in existing_columns:
        cursor.execute('ALTER TABLE user_logs ADD COLUMN rba_score INTEGER DEFAULT 0')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            credential_id TEXT    NOT NULL UNIQUE,
            public_key   TEXT    NOT NULL,
            sign_count   INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ips_blacklist (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            ip                  TEXT     NOT NULL UNIQUE,
            location            TEXT     NOT NULL DEFAULT 'Unknown',
            timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
            username            TEXT,
            status              TEXT     NOT NULL CHECK(status IN ('FAILED', 'BLOCKED')),
            blocked_until       DATETIME,
            attempt_count       INTEGER  NOT NULL DEFAULT 1,
            last_block_duration INTEGER
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
