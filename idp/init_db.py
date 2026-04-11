import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    conn = sqlite3.connect('seguranca.db')
    cursor = conn.cursor()

    # Tabela de Utilizadores
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

    # Tabela de Logs para RBA
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT -- 'SUCCESS', 'FAILED', 'BLOCKED'
        )
    ''')

    # Criar um user de teste (password: admin123)
    p_hash = generate_password_hash('admin123')
    try:
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ('admin', p_hash))
    except:
        pass 

    conn.commit()
    conn.close()
    print("Base de dados inicializada!")

if __name__ == '__main__':
    init_db()