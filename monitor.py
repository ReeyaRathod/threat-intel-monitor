from flask import Flask, render_template, request, redirect, url_for, session
import json
import os
import requests
import sqlite3
import random

app = Flask(__name__)
app.secret_key = "soc_secret_key_security_dashboard"

DB_FILE = "soc_database.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('analyst', 'secops2026')")
    conn.commit()
    conn.close()

init_db()

def fetch_live_threats_with_geo():
    triggered_alerts = []
    try:
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        response = requests.get(url, timeout=3)
        
        if response.status_code == 200:
            data = response.json()
            items = data.get("urls", [])[:5]
            
            for item in items:
                host = item.get("host", "malicious-host.com")
                # Generate realistic pseudo-coordinates or fetch geo if IP available
                # For portfolio stability, we assign realistic global threat lat/lng coordinates
                lat = random.uniform(-40, 60)
                lng = random.uniform(-150, 150)
                
                triggered_alerts.append({
                    "type": "warning",
                    "value": item.get("url", "malicious-endpoint.com")[:35] + "...",
                    "source": f"URLhaus [{item.get('reporter', 'Community')}]",
                    "date": item.get("date_added", "Recent"),
                    "lat": lat,
                    "lng": lng
                })
    except Exception:
        # Fallback offline geo-mocked threats
        triggered_alerts = [
            {"type": "email", "value": "admin@target-enterprise.com", "source": "DarkWeb Feed [Offline]", "date": "2026-10-30", "lat": 37.7749, "lng": -122.4194},
            {"type": "domain", "value": "target-enterprise-login.com", "source": "Typosquatting Monitor", "date": "2026-10-26", "lat": 51.5074, "lng": -0.1278},
            {"type": "keyword", "value": "internal credentials", "source": "Pastebin Scraping", "date": "2026-10-28", "lat": 35.6762, "lng": 139.6503}
        ]
    return triggered_alerts

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid Credentials. Try analyst / secops2026"
            
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    live_alerts = fetch_live_threats_with_geo()
    return render_template('index.html', alerts=live_alerts)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
