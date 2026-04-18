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
    # Connect using the absolute path so it works regardless of working directory
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            mfa_secret TEXT,
            is_locked INTEGER DEFAULT 0,
            lock_until DATETIME
        )
    ''')

    # Create login logs table for RBA if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT -- 'SUCCESS', 'FAILED', 'BLOCKED'
        )
    ''')

    # Insert default user if not already present, using credentials from .env
    p_hash = generate_password_hash(DEFAULT_PASSWORD)
    try:
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (DEFAULT_USER, p_hash))
    except:
        pass

    conn.commit()
    conn.close()
    print("[DB] Database initialized.")

if __name__ == '__main__':
    init_db()
