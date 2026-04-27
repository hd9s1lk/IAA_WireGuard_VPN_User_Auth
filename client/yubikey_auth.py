#!/usr/bin/env python3

import os
import sys
import json
import base64
import secrets
import hashlib
import hmac

SCRIPT_DIR = os.path.dirname(__file__)
CRED_FILE = os.path.join(SCRIPT_DIR, 'yubikey_sim.json')


def to_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=') .decode('ascii')


def from_base64url(value: str) -> bytes:
    padding = '=' * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def save_credential(credential):
    with open(CRED_FILE, 'w') as f:
        json.dump(credential, f)


def load_credential():
    if not os.path.exists(CRED_FILE):
        return None
    with open(CRED_FILE, 'r') as f:
        return json.load(f)


def register():
    credential_id = to_base64url(secrets.token_bytes(16))
    secret_key = to_base64url(secrets.token_bytes(32))
    credential = {
        'credential_id': credential_id,
        'public_key': secret_key,
        'sign_count': 0
    }
    save_credential(credential)
    print(json.dumps(credential))


def authenticate(credential_id=None):
    credential = load_credential()
    if not credential:
        raise SystemExit('No simulated Yubikey credential found. Register first.')
    if credential_id and credential_id != credential['credential_id']:
        raise SystemExit('Credential ID mismatch.')

    challenge = secrets.token_bytes(16)
    signature = hmac.new(from_base64url(credential['public_key']), challenge, hashlib.sha256).digest()
    credential['sign_count'] += 1
    save_credential(credential)
    print(json.dumps({
        'success': True,
        'credential_id': credential['credential_id'],
        'signature': to_base64url(signature),
        'challenge': to_base64url(challenge),
        'sign_count': credential['sign_count']
    }))


def main():
    if len(sys.argv) < 2:
        raise SystemExit('Usage: yubikey_auth.py register|auth [credential_id]')
    action = sys.argv[1]
    if action == 'register':
        register()
    elif action == 'auth':
        credential_id = sys.argv[2] if len(sys.argv) > 2 else None
        authenticate(credential_id)
    else:
        raise SystemExit('Unknown action: ' + action)


if __name__ == '__main__':
    main()
