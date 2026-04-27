import os
import sys
import subprocess
import io
import json
import base64
import pyotp
import qrcode
import geoip2.database
from dotenv import load_dotenv
from flask import Flask, request, render_template, session, redirect
from werkzeug.security import check_password_hash, generate_password_hash
import db.db_gateway as db_gateway
import db.init_db as init_db
import db.rba as rba
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

app = Flask(__name__, template_folder='html', static_folder='html', static_url_path='/static')
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'IAA')

FLASK_HOST  = os.getenv('FLASK_HOST', '127.0.0.1')
FLASK_PORT  = int(os.getenv('FLASK_PORT', 5000))
FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', 3))

GEOLITE_DB_PATH = os.path.join(os.path.dirname(__file__), 'resources', 'GeoLite2-City.mmdb')

RP_ID = os.getenv('RP_ID', '127.0.0.1')

def get_webauthn_credential(user_id):
    conn = db_gateway.get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE user_id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            'credential_id': row[0],
            'public_key': row[1],
            'sign_count': row[2]
        }
    return None

def has_webauthn_credential(user_id):
    conn = db_gateway.get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM webauthn_credentials WHERE user_id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row is not None


def run_yubikey_simulator(args):
    script_path = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'client', 'yubikey_auth.py'))
    command = [sys.executable, script_path] + args
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or 'Yubikey simulator failed')
    return json.loads(result.stdout)

def get_location_from_ip(ip: str) -> tuple[str, str]:
    try:
        with geoip2.database.Reader(GEOLITE_DB_PATH) as reader:
            response = reader.city(ip)
            city    = response.city.name
            country = response.country.name
            location = f"{city}, {country}" if city and country else (country or city or 'Unknown')
            return location, city or 'Unknown'
    except Exception:
        return 'Unknown', 'Unknown'


def generate_qr_code_base64(username: str, secret: str) -> str:
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name='Portal WireGuard')
    qr_img = qrcode.make(uri)
    buffer = io.BytesIO()
    qr_img.save(buffer, format='PNG')
    return base64.b64encode(buffer.getvalue()).decode()


@app.route('/')
def index():
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    success = session.pop('success_message', None)

    if request.method == 'POST':
        username   = request.form.get('username')
        password   = request.form.get('password')
        ip_address = request.remote_addr or 'unknown'
        location, city = get_location_from_ip(ip_address)

        is_blocked, wait_time = db_gateway.check_ip_blocked(ip_address)
        if is_blocked:
            return render_template('index.html', step='blocked', wait_time=wait_time)

        conn   = db_gateway.get_db()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT id, password_hash, mfa_secret, mfa_enabled FROM users WHERE username = ?',
            (username,)
        )
        user_record = cursor.fetchone()
        user_id     = user_record[0] if user_record else None

        if user_record and check_password_hash(user_record[1], password):
            session['user_id'] = user_id
            if user_record[3] == 0:
                session['register_username'] = username
                session['register_mfa_secret'] = user_record[2]
                conn.close()
                qr_code = generate_qr_code_base64(username, user_record[2])
                return render_template('index.html', step='register_qrcode', qr_code=qr_code)

            rba_score = rba.evaluate_rba(user_id, ip_address, city, cursor)

            db_gateway.insert_success_data(cursor, ip_address, user_id, location, username, city, rba_score)
            conn.commit()

            rba.add_known_ip(ip_address)
            conn.close()

            session['temp_user']  = username
            session['mfa_secret'] = user_record[2]
            session['rba_score'] = rba_score

            if True:
                return render_template('index.html', step='confirm')

            session['logged_in'] = True
            try:
                subprocess.run(['sudo', 'wg-quick', 'up', 'wg0'], capture_output=True)
            except Exception:
                pass
            return redirect('/dashboard')

        else:

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
                error=f"Attempts remaining: {failures}/{MAX_ATTEMPTS}",
                success=success
            )

    return render_template('index.html', step='login', success=success)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('index.html', step='register', error='Username and password are required.')

        conn = db_gateway.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            conn.close()
            return render_template('index.html', step='register', error='This username is already taken.')

        password_hash = generate_password_hash(password)
        mfa_secret = pyotp.random_base32()
        cursor.execute(
            'INSERT INTO users (username, password_hash, mfa_secret, mfa_enabled) VALUES (?, ?, ?, ?)',
            (username, password_hash, mfa_secret, 0)
        )
        conn.commit()
        conn.close()

        session['register_username'] = username
        session['register_mfa_secret'] = mfa_secret
        qr_code = generate_qr_code_base64(username, mfa_secret)
        return render_template('index.html', step='register_qrcode', qr_code=qr_code)

    return render_template('index.html', step='register')


@app.route('/register_complete', methods=['POST'])
def register_complete():
    username = session.get('register_username')
    secret = session.get('register_mfa_secret')
    otp = request.form.get('otp')

    if not username or not secret:
        return redirect('/login')

    if not otp:
        qr_code = generate_qr_code_base64(username, secret)
        return render_template('index.html', step='register_qrcode', qr_code=qr_code, error='Por favor insira o código de 6 dígitos.')

    totp = pyotp.TOTP(secret)
    if totp.verify(otp):
        conn = db_gateway.get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET mfa_enabled = 1 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        session.pop('register_username', None)
        session.pop('register_mfa_secret', None)
        session['success_message'] = 'Conta criada com sucesso, Autenticação Multi-Fator também.'
        return redirect('/login')

    qr_code = generate_qr_code_base64(username, secret)
    return render_template('index.html', step='register_qrcode', qr_code=qr_code, error='Código inválido. Tente novamente.')


@app.route('/yubikey')
def yubikey():
    if 'temp_user' not in session:
        return redirect('/login')
    user_id = session.get('user_id')
    has_cred = has_webauthn_credential(user_id)
    return render_template('index.html', step='yubikey', has_cred=has_cred)


@app.route('/yubikey_register_options')
def yubikey_register_options():
    user_id = session.get('user_id')
    username = session.get('temp_user')
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name="VPN Portal",
        user_id=user_id.to_bytes(4, 'big'),
        user_name=username,
        user_display_name=username
    )
    session['registration_challenge'] = options.challenge
    return options.to_dict()

@app.route('/yubikey_register', methods=['POST'])
def yubikey_register():
    if 'temp_user' not in session:
        return redirect('/login')
    try:
        result = run_yubikey_simulator(['register'])
    except Exception as exc:
        return render_template('index.html', step='yubikey', has_cred=False, error=str(exc))

    credential_id = result.get('credential_id')
    public_key = result.get('public_key')
    sign_count = result.get('sign_count', 0)
    user_id = session.get('user_id')
    conn = db_gateway.get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?)',
                   (user_id, credential_id, public_key, sign_count))
    conn.commit()
    conn.close()
    return redirect('/yubikey')

@app.route('/yubikey_verify', methods=['POST'])
def yubikey_verify():
    if 'temp_user' not in session:
        return redirect('/login')
    user_id = session.get('user_id')
    cred = get_webauthn_credential(user_id)
    if not cred:
        return render_template('index.html', step='yubikey', has_cred=False, error='No registered Yubikey credential.')
    try:
        result = run_yubikey_simulator(['auth', cred['credential_id']])
    except Exception as exc:
        return render_template('index.html', step='yubikey', has_cred=True, error=str(exc))
    if result.get('success'):
        session['logged_in'] = True
        try:
            subprocess.run(['sudo', 'wg-quick', 'up', 'wg0'], capture_output=True)
        except Exception:
            pass
        return redirect('/dashboard')
    return render_template('index.html', step='yubikey', has_cred=True, error='Yubikey authentication failed.')


@app.route('/qrcode')
def qrcode_page():
    if 'temp_user' not in session:
        return redirect('/login')

    secret = session.get('mfa_secret')
    username = session.get('temp_user')
    qr_code = generate_qr_code_base64(username, secret)
    return render_template('index.html', step='qrcode', qr_code=qr_code)


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
        except Exception:
            pass
        return redirect('/dashboard')

    return render_template('index.html', step='mfa', error='Invalid MFA code')


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
