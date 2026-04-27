import os
import sqlite3
from datetime import datetime

def load_known_ips():
    known_ips_file = os.path.join(os.path.dirname(__file__), 'knownIPs.txt')
    known_ips = set()
    try:
        with open(known_ips_file, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip:
                    known_ips.add(ip)
    except FileNotFoundError:
        pass
    return known_ips


def get_last_login_city(cursor: sqlite3.Cursor, user_id: int) -> str | None:
    cursor.execute(
        'SELECT city FROM user_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1',
        (user_id,)
    )
    row = cursor.fetchone()
    return row[0] if row else None


def get_failed_attempts_count(cursor: sqlite3.Cursor, ip: str) -> int:
    cursor.execute(
        'SELECT attempt_count FROM ips_blacklist WHERE ip = ?',
        (ip,)
    )
    row = cursor.fetchone()
    return row[0] if row else 0


def is_unusual_time(hour: int) -> bool:
    return hour < 6 or hour > 22


def evaluate_rba(user_id: int, ip: str, city: str, cursor: sqlite3.Cursor) -> int:
    known_ips = load_known_ips()
    ip_risk = 1.0 if ip not in known_ips else 0.0

    last_city = get_last_login_city(cursor, user_id)
    city_risk = 1.0 if last_city and last_city != city else 0.0

    failed_attempts = get_failed_attempts_count(cursor, ip)
    attempts_risk = 1.0 if failed_attempts > 3 else 0.0

    current_hour = datetime.now().hour
    time_risk = 1.0 if is_unusual_time(current_hour) else 0.0

    weights = {
        'ip': 0.40,
        'city': 0.30,
        'attempts': 0.20,
        'time': 0.10
    }

    rba_score = (
        weights['ip'] * ip_risk +
        weights['city'] * city_risk +
        weights['attempts'] * attempts_risk +
        weights['time'] * time_risk
    ) * 100

    return int(rba_score)


def add_known_ip(ip: str):
    known_ips_file = os.path.join(os.path.dirname(__file__), 'knownIPs.txt')
    known_ips = load_known_ips()
    if ip not in known_ips:
        with open(known_ips_file, 'a') as f:
            f.write(f"{ip}\n")
