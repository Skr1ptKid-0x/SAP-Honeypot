import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for
import logging

app = Flask(__name__)

# --- DATABASE SETUP ---
DB_NAME = "honeypot.db"

def init_db():
    """Initializes the SQLite database to store captured credentials."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            username TEXT,
            password TEXT,
            user_agent TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_attack(ip, user, pwd, agent):
    """Inserts the captured attack data into the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO attacks (timestamp, ip_address, username, password, user_agent) VALUES (?, ?, ?, ?, ?)",
                   (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, user, pwd, agent))
    conn.commit()
    conn.close()
    # Console alert for the admin
    print(f"\n[!] ALERT: Attack Detected from {ip} | User: {user} | Pass: {pwd}")

# --- ROUTES ---

@app.route('/', methods=['GET', 'POST'])
def login():
    """
    The Trap: Mimics an SAP NetWeaver Login Screen.
    """
    if request.method == 'POST':
        # Capture the data
        username = request.form.get('sap-user')
        password = request.form.get('sap-password')
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Log it silently
        log_attack(ip_address, username, password, user_agent)
        
        # Fake a login error (Stall the attacker)
        return render_template('login.html', error="Logon failed. Correct the entries.")
        
    return render_template('login.html')

@app.route('/admin_dashboard')
def admin():
    """
    Internal Intelligence Dashboard to view captured logs.
    In a real scenario, this should be protected by strong auth.
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attacks ORDER BY id DESC")
    logs = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', logs=logs)

if __name__ == '__main__':
    print("[*] Initializing SAP Honeypot System...")
    init_db()
    print("[*] SAP NetWeaver Trap is running on port 8080...")
    app.run(host='0.0.0.0', port=8080, debug=False)
