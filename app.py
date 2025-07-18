import os
import sqlite3
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.security import generate_password_hash, check_password_hash
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

DATABASE = 'users.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password_hash TEXT NOT NULL,
                            email TEXT NOT NULL,
                            is_admin INTEGER DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS reset_tokens (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            token TEXT NOT NULL,
                            expires_at DATETIME NOT NULL,
                            FOREIGN KEY(user_id) REFERENCES users(id))''')
init_db()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
@app.route("/landing")
def landing():
    return render_template("landing.html")

@app.route('/anzeige')
def anzeigen():
    timestamp = int(datetime.now().timestamp())
    return render_template("anzeigen.html", timestamp=timestamp)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'screenshot.png')
            file.save(filepath)
            return redirect(url_for('anzeigen'))
    return render_template('upload.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('landing'))
        flash('Login fehlgeschlagen.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    conn = get_db_connection()
    if request.method == 'POST':
        if 'delete' in request.form:
            user_id = request.form['delete']
            conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
        else:
            username = request.form['new_username']
            password = generate_password_hash(request.form['new_password'])
            email = request.form['new_email']
            is_admin = 1 if 'new_admin' in request.form else 0
            conn.execute('INSERT INTO users (username, password_hash, email, is_admin) VALUES (?, ?, ?, ?)',
                         (username, password, email, is_admin))
            conn.commit()
    users = conn.execute('SELECT * FROM users').fetchall()
    return render_template('admin.html', users=users)

@app.route('/reset', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user:
            # Lösche alte Tokens
            conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user['id'],))
            token = secrets.token_urlsafe(32)
            expires = datetime.now() + timedelta(minutes=10)
            conn.execute("INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)", 
             (user['id'], token, expires.isoformat()))
            conn.commit()
            print("Reset-Anfrage empfangen für E-Mail:", email)

            # Sende E-Mail
            reset_link = f"http://192.168.1.234:5000/reset/{token}"  # <== Anpassen an Domain
            subject = "Passwort zurücksetzen"
            body = f"""Klicke auf den folgenden Link, um dein Passwort zurückzusetzen:
{reset_link}

Der Link ist 10 Minuten gültig."""
            send_email(subject, body, email)
        flash('Wenn die E-Mail existiert, wurde ein Link gesendet.')
    return render_template('reset_request.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    conn = get_db_connection()
    conn.execute("DELETE FROM reset_tokens WHERE expires_at < ?", (datetime.now(),))
    token_entry = conn.execute("SELECT * FROM reset_tokens WHERE token = ?", (token,)).fetchone()
    if not token_entry:
        flash('Token ist ungültig oder abgelaufen.')
        return redirect(url_for('reset_request'))
    if request.method == 'POST':
        password = generate_password_hash(request.form['password'])
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password, token_entry['user_id']))
        conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (token_entry['user_id'],))
        conn.commit()
        flash('Passwort erfolgreich geändert.')
        return redirect(url_for('login'))
    return render_template('reset_token.html')

def send_email(subject, body, to_email):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = "support@to-labsystems.de"  # Platzhalter
    msg['To'] = to_email
    msg.set_content(body)
    with smtplib.SMTP('smtp.office365.com', 587) as smtp:
        smtp.starttls()
        smtp.login('bjs@to-labsystems.de', 'Kloakering2025!')  # Platzhalter
        smtp.send_message(msg)
        
@app.route('/update_user', methods=['POST'])
def update_user():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    user_id = request.form['user_id']
    email = request.form['email']
    is_admin = int(request.form.get('is_admin', 0))
    new_password = request.form.get('new_password', '')

    conn = get_db_connection()
    if new_password:
        password_hash = generate_password_hash(new_password)
        conn.execute("UPDATE users SET email = ?, is_admin = ?, password_hash = ? WHERE id = ?",
                     (email, is_admin, password_hash, user_id))
    else:
        conn.execute("UPDATE users SET email = ?, is_admin = ? WHERE id = ?",
                     (email, is_admin, user_id))
    conn.commit()
    conn.close()
    flash("Benutzer erfolgreich aktualisiert.")
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)