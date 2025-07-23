import os
import sqlite3
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, jsonify
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
    conn = get_db_connection()
    today = datetime.today().date()
    announcements = conn.execute('''
        SELECT * FROM announcements
        WHERE expires_at IS NULL OR date(expires_at) >= ?
        ORDER BY created_at DESC
    ''', (today,)).fetchall()
    conn.close()
    return render_template("landing.html", announcements=announcements)

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
            session['username'] = user['username']
            return redirect(url_for('landing'))
        flash('Login fehlgeschlagen.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))

@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    conn = get_db_connection()
    if request.method == 'POST':
        if 'delete' in request.form:
            user_id = request.form['delete']
            conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        else:
            username = request.form['new_username']
            password = generate_password_hash(request.form['new_password'])
            email = request.form['new_email']
            is_admin = 1 if 'new_admin' in request.form else 0
            conn.execute('INSERT INTO users (username, password_hash, email, is_admin) VALUES (?, ?, ?, ?)',
                         (username, password, email, is_admin))
        conn.commit()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

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
            reset_link = f"http://produktion.to-labsystems.de/reset/{token}"  # <== Anpassen an Domain
            subject = "Passwort zurücksetzen"
            body = f"""Klicke auf den folgenden Link, um dein Passwort zurückzusetzen:
{reset_link}

Der Link ist 10 Minuten gültig."""
            send_email(subject, body, email)
        flash('Wenn die E-Mail existiert, wurde ein Link gesendet.')
    return render_template('reset_request.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    with get_db_connection() as conn:
        # Abgelaufene Tokens löschen
        conn.execute("DELETE FROM reset_tokens WHERE expires_at < ?", (datetime.now(),))
        token_entry = conn.execute("SELECT * FROM reset_tokens WHERE token = ?", (token,)).fetchone()

    if not token_entry:
        flash('Token ist ungültig oder abgelaufen.')
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if not new_password:
            flash("Neues Passwort darf nicht leer sein.")
            return redirect(request.url)

        password_hash = generate_password_hash(new_password)

        print("🔁 Passwort-Reset-Versuch:")
        print("➡️ Neue Hash:", password_hash)
        print("➡️ Benutzer-ID:", token_entry['user_id'])

        with get_db_connection() as conn:
            result = conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, token_entry['user_id'])
            )
            conn.execute(
                "DELETE FROM reset_tokens WHERE user_id = ?",
                (token_entry['user_id'],)
            )
            conn.commit()

            print("✅ Passwort geändert:", result.rowcount, "Zeile(n) aktualisiert.")

        flash('Passwort erfolgreich geändert.')
        return redirect(url_for('login'))

    return render_template('reset_token.html')


def send_email(subject, body, to_email):
    import smtplib
    from email.message import EmailMessage
    import traceback

    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = "it@to-labsystems.de"  # z. B. info@deine-domain.de
        msg['To'] = to_email
        msg.set_content(body)

        # Port 465 = SSL
        with smtplib.SMTP_SSL('smtp.strato.de', 465, timeout=10) as smtp:
            smtp.login('it@to-labsystems.de', 'Labsys-InfoTech25/')
            smtp.send_message(msg)

        print("✅ E-Mail erfolgreich gesendet an", to_email)

    except Exception as e:
        print("❌ Fehler beim Senden der E-Mail:")
        traceback.print_exc()
        
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

@app.route('/admin/ankuendigung', methods=['GET', 'POST'])
def manage_announcements():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    conn = get_db_connection()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form.get('content', '')
        source = request.form['source']
        expires_at = request.form.get('expires_at') or None
        file = request.files.get('attachment')
        attachment_path = None

        if file and file.filename:
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(save_path)
            attachment_path = file.filename

        conn.execute('''
            INSERT INTO announcements (title, content, source, attachment_path, expires_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (title, content, source, attachment_path, expires_at, session.get('user_id')))
        conn.commit()

    if 'delete_id' in request.args:
        conn.execute('DELETE FROM announcements WHERE id = ?', (request.args['delete_id'],))
        conn.commit()
        return redirect(url_for('manage_announcements'))

    announcements = conn.execute('SELECT * FROM announcements ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('manage_announcements.html', announcements=announcements)

@app.route('/api/announcements')
def api_announcements():
    conn = get_db_connection()
    today = datetime.today().date()
    rows = conn.execute('''
        SELECT id, title, content, source, attachment_path
        FROM announcements
        WHERE expires_at IS NULL OR date(expires_at) >= ?
        ORDER BY created_at DESC
    ''', (today,)).fetchall()
    conn.close()

    announcements = [dict(row) for row in rows]
    return jsonify(announcements)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)