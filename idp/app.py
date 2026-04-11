import sqlite3
import time
import subprocess
import io
import base64
import pyotp
import qrcode
from flask import Flask, request, render_template_string, session, redirect
from werkzeug.security import check_password_hash

app = Flask(__name__, static_folder='images', static_url_path='/images')
app.secret_key = 'IAA'


DB_NAME = 'seguranca.db'
MAX_ATTEMPTS = 3
LOCK_TIME = 15


def get_db():
    conn = sqlite3.connect(DB_NAME)
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

BASE_HTML = """
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: sans-serif; background: linear-gradient(rgba(255,255,255,0.85), rgba(255,255,255,0.85)), url('/images/wireguard.jpg') center/cover fixed no-repeat; text-align: center; padding: 50px; }
        .card { background: rgba(255,255,255,0.92); padding: 30px; border-radius: 10px; display: inline-block; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        input { display: block; margin: 10px auto; padding: 10px; width: 200px; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; cursor: pointer; border-radius: 5px; }
        .error { color: red; margin-bottom: 10px; }
        .success { color: green; }
        .mfa-logo { width: 120px; margin: 0 auto 20px; display: block; }
        .confirm-image { width: 160px; margin: 0 auto 20px; display: block; cursor: pointer; }
        .confirm-link { text-decoration: none; color: inherit; }
        .confirm-grid { display: flex; gap: 20px; justify-content: center; flex-wrap: wrap; margin-top: 20px; }
        .confirm-card { background: #f7f7f7; border: 1px solid #ddd; border-radius: 12px; padding: 20px; width: 220px; transition: transform 0.2s, box-shadow 0.2s; }
        .confirm-card:hover { transform: translateY(-3px); box-shadow: 0 8px 16px rgba(0,0,0,0.1); }
        .confirm-card h3 { margin-bottom: 12px; }
        .confirm-card p { margin-top: 0; color: #555; }
    </style>
    <title>Portal VPN - Projeto IAA</title>
</head>
<body>
    <div class="card">
        {% if step == 'login' %}
            <h2>Login Wireguard</h2>
            {% if error %}<p class="error">{{ error }}</p>{% endif %}
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Utilizador" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Próximo</button>
            </form>
        {% elif step == 'blocked' %}
            <h2>Foste bloqueado</h2>
            <p>Tempo Restante: <span id="countdown">{{ wait_time }}</span>s</p>
            <script>
                let remaining = {{ wait_time }};
                const countdown = document.getElementById('countdown');
                const interval = setInterval(() => {
                    remaining -= 1;
                    if (remaining <= 0) {
                        clearInterval(interval);
                        window.location.href = '/login';
                    } else {
                        countdown.textContent = remaining;
                    }
                }, 1000);
            </script>
        {% elif step == 'confirm' %}
            <h2>Confirmar Identidade</h2>
            <div class="confirm-grid">
                <a href="/qrcode" class="confirm-card confirm-link">
                    <h3>TOTP</h3>
                    <img src="/images/TOTP.jpeg" alt="TOTP Setup" class="confirm-image">
                    <p>Gerar QR Code TOTP</p>
                </a>
                <a href="/mfa" class="confirm-card confirm-link">
                    <h3>Google Authenticator</h3>
                    <img src="/images/authenticator.png" alt="Authenticator Logo" class="confirm-image">
                    <p>Introduzir código existente</p>
                </a>
            </div>
        {% elif step == 'qrcode' %}
            <img src="/images/authenticator.png" alt="Authenticator Logo" class="mfa-logo">
            <h2>Gerar QR Code</h2>
            <p>Scan o QR Code com a app de autenticação e depois introduza o código abaixo.</p>
            <img src="data:image/png;base64,{{ qr_code }}" alt="QR Code TOTP" class="confirm-image">
            {% if error %}<p class="error">{{ error }}</p>{% endif %}
            <form method="POST" action="/mfa">
                <input type="text" name="otp" placeholder="000000" required>
                <button type="submit">Ativar a VPN</button>
            </form>
        {% elif step == 'mfa' %}
            <img src="/images/authenticator.png" alt="Authenticator Logo" class="mfa-logo">
            <h2>Google Authenticator</h2>
            <p>Introduza o código</p>
            {% if error %}<p class="error">{{ error }}</p>{% endif %}
            <form method="POST" action="/mfa">
                <input type="text" name="otp" placeholder="000000" required>
                <button type="submit">Ativar a VPN</button>
            </form>
        {% elif step == 'dashboard' %}
            <h2 class="success">Bem-Vindo a VPN WireGuard!</h2>
            <pre>{{ wg_status }}</pre>
            <a href="/logout"><button style="background:red">Desligar</button></a>
        {% endif %}
    </div>
</body>
</html>
"""

#routes

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr or 'unknown'
        
        allowed, wait_time = check_rba_status(ip_address)
        if not allowed:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO login_logs (username, ip_address, status) VALUES (?, ?, "BLOCKED")', (username, ip_address))
            conn.commit()
            conn.close()
            return render_template_string(BASE_HTML, step='blocked', wait_time=wait_time)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, mfa_secret FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[0], password):
            cursor.execute('INSERT INTO login_logs (username, ip_address, status) VALUES (?, ?, "SUCCESS")', (username, ip_address))
            conn.commit()
            conn.close()
            session['temp_user'] = username
            session['mfa_secret'] = user[1]
            return render_template_string(BASE_HTML, step='confirm')
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
            return render_template_string(BASE_HTML, step='login', error=f"Tentativas Restantes: ({failures}/{MAX_ATTEMPTS})")

    return render_template_string(BASE_HTML, step='login')

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

    return render_template_string(BASE_HTML, step='qrcode', qr_code=qr_b64)

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'temp_user' not in session:
        return redirect('/login')

    if request.method == 'GET':
        return render_template_string(BASE_HTML, step='mfa')

    otp = request.form.get('otp')
    totp = pyotp.TOTP(session['mfa_secret'])
    if totp.verify(otp):
        session['logged_in'] = True
        try:
            subprocess.run(['sudo', 'wg-quick', 'up', 'wg0'], capture_output=True)
        except:
            pass
        return redirect('/dashboard')

    return render_template_string(BASE_HTML, step='mfa', error="Código MFA inválido")

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'): return redirect('/login')
    status = subprocess.run(['sudo', 'wg', 'show'], capture_output=True, text=True).stdout
    return render_template_string(BASE_HTML, step='dashboard', wg_status=status)

@app.route('/logout')
def logout():
    subprocess.run(['sudo', 'wg-quick', 'down', 'wg0'], capture_output=True)
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    conn = get_db()
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
    
    app.run(host='0.0.0.0', port=5000, debug=True)
