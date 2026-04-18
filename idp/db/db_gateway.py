import os
import sqlite3
import time
from dotenv import load_dotenv

# Load .env from the project root (two levels above db/)
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))

MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', 3))
LOCK_TIME = int(os.getenv('LOCK_TIME', 15))

# Build the absolute path from DB_FILE: always stored in db/data/
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', os.getenv('DB_FILE', 'data.db'))

def get_db():
    # Connect using the absolute path so it works regardless of working directory
    conn = sqlite3.connect(DB_PATH)
    return conn

def check_rba_status(ip_address):
    conn = get_db()
    cursor = conn.cursor()
    window = f"-{LOCK_TIME} seconds"
    cursor.execute(
        'SELECT COUNT(*), MIN(strftime("%s", timestamp)) FROM login_logs '
        'WHERE ip_address = ? AND status = "FAILED" AND timestamp > datetime("now", ?)',
        (ip_address, window)
    )
    failures, oldest = cursor.fetchone()
    conn.close()

    if failures >= MAX_ATTEMPTS:
        wait_time = LOCK_TIME
        if oldest:
            elapsed = int(time.time() - int(oldest))
            wait_time = max(0, LOCK_TIME - elapsed)
        return False, wait_time
    return True, 0