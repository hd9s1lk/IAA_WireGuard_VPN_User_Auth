# IAA WireGuard VPN User Auth Portal

This project implements a secure user authentication portal for WireGuard VPN with multi-factor authentication (MFA), Risk-Based Authentication (RBA), and FIDO2 support.

## Features
- User registration and login
- TOTP MFA with QR code setup
- Risk-Based Authentication (RBA) scoring
- FIDO2/WebAuthn authentication with simulated Yubikey
- WireGuard VPN activation after successful auth

## Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Initialize the database:
   ```bash
   python3 idp/db/init_db.py
   ```

3. Run the server:
   ```bash
   python3 idp/auth_server.py
   ```

4. Access the portal at http://127.0.0.1:5000

## Default Credentials
- Username: admin
- Password: admin123

## Project Structure
- `idp/`: Authentication server and web interface
- `client/yubikey_auth.py`: Simulated FIDO2 device
- `requirements.txt`: Python dependencies

## Authors
Pedro Costa, Henrique Dias, Jorge Saénz