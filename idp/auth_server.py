# Auth server — OAuth 2.0 / Device Flow

import os
import subprocess
import io
import base64
import pyotp
import qrcode
import geoip2.database
from dotenv import load_dotenv
from flask import Flask, request, render_template, session, redirect
from werkzeug.security import check_password_hash
import db.db_gateway as db_gateway
import db.init_db as init_db

# Load .env from the project root (one level above idp/)
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

app = Flask(__name__, template_folder='html', static_folder='html', static_url_path='/static')
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'IAA')

FLASK_HOST  = os.getenv('FLASK_HOST', '127.0.0.1')
FLASK_PORT  = int(os.getenv('FLASK_PORT', 5000))
FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', 3))

GEOLITE_DB_PATH = os.path.join(os.path.dirname(__file__), 'resources', 'GeoLite2-City.mmdb')

# ─── Helpers ────────────────────────────────────────────────────────────────

def get_location_from_ip(ip: str) -> str:
    try:
        with geoip2.database.Reader(GEOLITE_DB_PATH) as reader:
            response = reader.city(ip)
            city    = response.city.name
            country = response.country.name
            if city and country:
                return f"{city}, {country}"
            return country or city or 'Unknown'
    except Exception:
        return 'Unknown'

# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username   = request.form.get('username')
        password   = request.form.get('password')
        ip_address = request.remote_addr or 'unknown'
        location   = get_location_from_ip(ip_address)

        is_blocked, wait_time = db_gateway.check_ip_blocked(ip_address)
        if is_blocked:
            return render_template('index.html', step='blocked', wait_time=wait_time)
        
        conn   = db_gateway.get_db()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT id, password_hash, mfa_secret FROM users WHERE username = ?',
            (username,)
        )
        user_record = cursor.fetchone()
        user_id     = user_record[0] if user_record else None

        if user_record and check_password_hash(user_record[1], password): #TODO importar check_password_hash com as alguma coisa para se destinguir
            # ── Success ──────────────────────────────────────────────────────
            #TODO verificar RAS
            db_gateway.insert_success_data(cursor, ip_address, user_id, location, username)
            conn.commit()
            conn.close()
            session['temp_user']  = username
            session['mfa_secret'] = user_record[2]
            return render_template('index.html', step='confirm')

        else:
            # ── Failed attempt ────────────────────────────────────────────────

            db_gateway.insert_failed_attempt(cursor, ip_address, location, username)
            failures = db_gateway.get_recent_failure_count(cursor, ip_address)

            if failures >= MAX_ATTEMPTS:
                block_duration = db_gateway.get_next_block_duration(ip_address)
                db_gateway.insert_blocked(cursor, ip_address, location, username, block_duration)
                conn.commit()
                conn.close()
                return render_template('index.html', step='blocked', wait_time=block_duration)

            conn.commit()
            conn.close()
            return render_template(
                'index.html', step='login',
                error=f"Attempts remaining: {failures}/{MAX_ATTEMPTS}"
            )

    return render_template('index.html', step='login')


@app.route('/qrcode')
def qrcode_page():
    if 'temp_user' not in session:
        return redirect('/login')

    secret   = session.get('mfa_secret')
    username = session.get('temp_user')
    totp     = pyotp.TOTP(secret)
    uri      = totp.provisioning_uri(name=username, issuer_name='Portal WireGuard')

    qr_img = qrcode.make(uri)
    buffer = io.BytesIO()
    qr_img.save(buffer, format='PNG')
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template('index.html', step='qrcode', qr_code=qr_b64)


@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'temp_user' not in session:
        return redirect('/login')

    if request.method == 'GET':
        return render_template('index.html', step='mfa')

    otp  = request.form.get('otp')
    totp = pyotp.TOTP(session['mfa_secret'])
    if totp.verify(otp):
        session['logged_in'] = True
        try:
            subprocess.run(['sudo', 'wg-quick', 'up', 'wg0'], capture_output=True)
        except Exception:
            pass
        return redirect('/dashboard')

    return render_template('index.html', step='mfa', error="Invalid MFA code")


@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect('/login')
    status = subprocess.run(['sudo', 'wg', 'show'], capture_output=True, text=True).stdout
    return render_template('index.html', step='dashboard', wg_status=status)


@app.route('/logout')
def logout():
    subprocess.run(['sudo', 'wg-quick', 'down', 'wg0'], capture_output=True)
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    init_db.init_db()

    conn   = db_gateway.get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT mfa_secret FROM users WHERE username = "admin"')
    row = cursor.fetchone()
    if row and not row[0]:
        new_secret = pyotp.random_base32()
        cursor.execute('UPDATE users SET mfa_secret = ? WHERE username = "admin"', (new_secret,))
        conn.commit()
        print(f"\n[MFA] new_secret = {new_secret}")
        print("[MFA] Configure in Google Authenticator manually or use a QR generator.")
    conn.close()

    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
