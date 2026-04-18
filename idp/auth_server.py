# Lógica OAuth 2.0 / Device Flow

import os
import subprocess
import io
import base64
import pyotp
import qrcode
from dotenv import load_dotenv
from flask import Flask, request, render_template, session, redirect
from werkzeug.security import check_password_hash
import db.db_gateway as db_gateway
import db.init_db as init_db

# Load .env from the project root (one level above idp/)
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

app = Flask(__name__, template_folder='html', static_folder='html', static_url_path='/static')
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'IAA')

# Falls back to localhost if not defined in .env
FLASK_HOST = os.getenv('FLASK_HOST', '127.0.0.1')
FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))
FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', 3))
LOCK_TIME = int(os.getenv('LOCK_TIME', 15))


# routes

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr or 'unknown'

        allowed, wait_time = db_gateway.check_rba_status(ip_address)
        if not allowed:
            conn = db_gateway.get_db()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO login_logs (username, ip_address, status) VALUES (?, ?, "BLOCKED")', (username, ip_address))
            conn.commit()
            conn.close()
            return render_template('index.html', step='blocked', wait_time=wait_time)

        conn = db_gateway.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, mfa_secret FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[0], password):
            cursor.execute('INSERT INTO login_logs (username, ip_address, status) VALUES (?, ?, "SUCCESS")', (username, ip_address))
            conn.commit()
            conn.close()
            session['temp_user'] = username
            session['mfa_secret'] = user[1]
            return render_template('index.html', step='confirm')
        else:
            # Registar falha para RBA por IP
            cursor.execute('INSERT INTO login_logs (username, ip_address, status) VALUES (?, ?, "FAILED")', (username, ip_address))
            window = f"-{LOCK_TIME} seconds"
            cursor.execute(
                'SELECT COUNT(*) FROM login_logs WHERE ip_address = ? AND status = "FAILED" '
                'AND timestamp > datetime("now", ?)',
                (ip_address, window)
            )
            failures = cursor.fetchone()[0]
            conn.commit()
            conn.close()
            return render_template('index.html', step='login', error=f"Tentativas Restantes: ({failures}/{MAX_ATTEMPTS})")

    return render_template('index.html', step='login')

@app.route('/qrcode')
def qrcode_page():
    if 'temp_user' not in session:
        return redirect('/login')

    secret = session.get('mfa_secret')
    username = session.get('temp_user')
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name='Portal WireGuard')

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

    otp = request.form.get('otp')
    totp = pyotp.TOTP(session['mfa_secret'])
    if totp.verify(otp):
        session['logged_in'] = True
        try:
            subprocess.run(['sudo', 'wg-quick', 'up', 'wg0'], capture_output=True)
        except:
            pass
        return redirect('/dashboard')

    return render_template('index.html', step='mfa', error="Código MFA inválido")

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
    # Initialize database: creates tables and default user if they don't exist
    init_db.init_db()

    conn = db_gateway.get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT mfa_secret FROM users WHERE username = "admin"')
    row = cursor.fetchone()
    if row and not row[0]:
        new_secret = pyotp.random_base32()
        cursor.execute('UPDATE users SET mfa_secret = ? WHERE username = "admin"', (new_secret,))
        conn.commit()
        print(f"\n[MFA] new_secret_ = {new_secret}")
        print("[MFA] Configura no Google Authenticator com este código manualmente ou usa um gerador de QR.")
    conn.close()

    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
