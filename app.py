import os
import sqlite3
import secrets
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, jsonify
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from email.message import EmailMessage
from werkzeug.utils import secure_filename  # <— falls noch nicht importiert

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

# Upload/Diagramm-Config
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif', 'svg'}
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB pro Request

csrf = CSRFProtect(app)

# Basisordner für die Diagramme
DIAGRAM_BASE = os.path.join('static', 'diagramme', 'ausschussquote')

DIAGRAM_TYPES = {
    'produktivitaet':       'Produktivität',
    'stueckzahlen':         'Stückzahlen [GE]',
    'lieferzeit':           'Lieferzeit',
    'termintreue':          'Termintreue',
    'fertigungsqualitaet':  'Fertigungsqualität',
    'prozesstoerung':       'Prozesstörung',
}

# Ordner anlegen
os.makedirs(DIAGRAM_BASE, exist_ok=True)
for key in DIAGRAM_TYPES:
    os.makedirs(os.path.join(DIAGRAM_BASE, key), exist_ok=True)
    
def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file_storage, target_folder: str) -> str:
    original_name = secure_filename(file_storage.filename or "")
    if not original_name or not allowed_file(original_name):
        raise ValueError("Ungültiger Dateityp.")

    ext = original_name.rsplit('.', 1)[1].lower()
    unique_filename = f"{uuid.uuid4().hex}.{ext}"
    full_dir = os.path.join(app.config['UPLOAD_FOLDER'], target_folder)
    os.makedirs(full_dir, exist_ok=True)
    file_storage.save(os.path.join(full_dir, unique_filename))
    return os.path.join(target_folder, unique_filename).replace("\\", "/")

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
        cursor.execute('''CREATE TABLE IF NOT EXISTS trainings (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            title TEXT NOT NULL,
                            date TEXT NOT NULL,
                            time TEXT,
                            participants TEXT,
                            status TEXT DEFAULT 'geplant')''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS announcements (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            title TEXT NOT NULL,
                            content TEXT NOT NULL,
                            source TEXT,
                            attachment_path TEXT,
                            expires_at DATETIME,
                            created_by INTEGER,
                            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY(created_by) REFERENCES users(id))''')
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
    screenshot_path = request.args.get("image", "screenshots/screenshot.png")
    return render_template("anzeigen.html", timestamp=timestamp, screenshot_path=screenshot_path)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not file.filename:
            flash("Bitte eine Datei auswählen.")
            return redirect(url_for('upload'))
        try:
            screenshot_path = save_uploaded_file(file, 'screenshots')
        except ValueError:
            flash("Ungültiger Dateityp. Erlaubt sind nur Bilddateien.")
            return redirect(url_for('upload'))
        return redirect(url_for('anzeigen', image=screenshot_path))
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
    return redirect(url_for('admin_users'))

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
            try:
                attachment_path = save_uploaded_file(file, 'announcements')
            except ValueError:
                flash("Ungültiger Dateityp. Erlaubt sind nur Bilddateien.")
                conn.close()
                return redirect(url_for('manage_announcements'))

        conn.execute('''
            INSERT INTO announcements (title, content, source, attachment_path, expires_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (title, content, source, attachment_path, expires_at, session.get('user_id')))
        conn.commit()

    if request.method == 'POST' and 'delete_id' in request.form:
        conn.execute('DELETE FROM announcements WHERE id = ?', (request.form['delete_id'],))
        conn.commit()
        conn.close()
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

@app.route('/schulungen')
def schulungen():
    conn = get_db_connection()
    all_trainings = conn.execute('SELECT * FROM trainings ORDER BY date ASC').fetchall()

    # Nur Schulungen in den nächsten 30 Tagen
    today = datetime.today().date()
    in_30_days = (today + timedelta(days=30)).isoformat()
    upcoming = conn.execute('''
        SELECT * FROM trainings
        WHERE date BETWEEN ? AND ?
        ORDER BY date ASC
    ''', (today.isoformat(), in_30_days)).fetchall()

    conn.close()
    return render_template('trainings.html', trainings=all_trainings, upcoming=upcoming)


@app.route('/api/trainings')
def api_trainings():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM trainings
        WHERE
            date > DATE('now')
            OR (date = DATE('now') AND (time IS NULL OR time >= TIME('now')))
        ORDER BY date ASC, time ASC
    """).fetchall()
    conn.close()

    events = []
    for row in rows:
        title = row['title']
        if row['time']:
            title += f" ({row['time']})"

        events.append({
            "title": title,
            "start": row['date'],   # YYYY-MM-DD
            "allDay": True,
            "extendedProps": {
                "participants": row['participants'] or ""
            }
        })

    return jsonify(events)



@app.route('/admin/trainings', methods=['GET', 'POST'])
def admin_trainings():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        date = request.form['date']
        time = request.form.get('time')
        participants = request.form.get('participants')

        conn = get_db_connection()
        conn.execute("""
            INSERT INTO trainings (title, date, time, participants)
            VALUES (?, ?, ?, ?)
        """, (title, date, time, participants))
        conn.commit()
        conn.close()

        flash("Schulung erfolgreich hinzugefügt.")
        return redirect(url_for('admin_trainings'))

    # GET: Liste anzeigen
    conn = get_db_connection()
    trainings = conn.execute("SELECT * FROM trainings ORDER BY date DESC, time DESC").fetchall()
    conn.close()
    return render_template('admin_trainings.html', trainings=trainings)

@app.route('/admin/trainings/<int:tid>/delete', methods=['POST'])
def admin_trainings_delete(tid):
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute("DELETE FROM trainings WHERE id = ?", (tid,))
    conn.commit()
    conn.close()
    flash("Schulung gelöscht.")
    return redirect(url_for('admin_trainings'))


@app.route('/api/trainings/upcoming')
def api_upcoming_trainings():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM trainings
        WHERE date BETWEEN DATE('now') AND DATE('now', '+30 day')
        ORDER BY date ASC, time ASC
    """).fetchall()
    conn.close()

    html = ""
    for t in rows:
        title = t['title']
        date = t['date']
        time = t['time']
        participants = (t['participants'] or "").strip()

        display = f"<strong>{date}</strong> – {title}"
        if time:
            display += f", {time}"

        if participants:
            # als kleine Liste darunter
            plist = "".join(f"<li>{p.strip()}</li>" for p in participants.split(",") if p.strip())
            display += f"<div class='mt-1'><em>Teilnehmer:</em><ul class='mb-0'>{plist}</ul></div>"

        html += f"<li class='list-group-item'>{display}</li>"

    return html

@app.route('/admin/upload_qualimatrix', methods=['GET', 'POST'])
def upload_qualimatrix():
    # Optional: nur eingeloggte Admins – falls du nur Login willst, ersetze durch "if not session.get('user_id')"
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        updated = []
        for key, label in DIAGRAM_TYPES.items():
            # mehrere Dateien pro Feld
            files = request.files.getlist(key)
            # es wurde nichts ausgewählt
            files = [f for f in files if f and f.filename]

            if not files:
                continue

            target_dir = os.path.join(DIAGRAM_BASE, key)
            # Ordner leeren = "überschreiben"
            for name in os.listdir(target_dir):
                try:
                    os.remove(os.path.join(target_dir, name))
                except Exception:
                    pass

            # neue Dateien speichern
            invalid_files = []
            for f in files:
                safe_name = secure_filename(f.filename)
                if not allowed_file(safe_name):
                    invalid_files.append(f.filename)
                    continue
                ext = safe_name.rsplit('.', 1)[1].lower()
                unique_name = f"{uuid.uuid4().hex}.{ext}"
                f.save(os.path.join(target_dir, unique_name))

            if invalid_files:
                flash(
                    f"Ungültiger Dateityp in {label}: {', '.join(invalid_files)}. "
                    "Erlaubt sind nur Bilddateien."
                )
                return redirect(url_for('upload_qualimatrix'))

            updated.append(label)

        if updated:
            flash(f"Upload erfolgreich für: {', '.join(updated)}")
        else:
            flash("Keine Dateien ausgewählt.")

        return redirect(url_for('upload_qualimatrix'))

    # GET
    return render_template('upload_qualimatrix.html', diagram_types=DIAGRAM_TYPES)

# ---- Helfer: Daten für Qualimatrix sammeln (Gruppen + flache Liste) ----
def collect_qualimatrix_data():
    groups = []
    all_images = []
    for key, label in DIAGRAM_TYPES.items():
        folder = os.path.join(DIAGRAM_BASE, key)
        images = []
        if os.path.isdir(folder):
            files = [
                f for f in os.listdir(folder)
                if os.path.isfile(os.path.join(folder, f)) and allowed_file(f)
            ]
            files.sort(key=lambda n: os.path.getmtime(os.path.join(folder, n)), reverse=True)
            for name in files:
                path = os.path.join(folder, name)
                item = {
                    "src": url_for('static', filename=f'diagramme/ausschussquote/{key}/{name}'),
                    "name": name,
                    "mtime": os.path.getmtime(path),
                    "key": key,
                    "label": label,
                }
                images.append(item)
                all_images.append(item)
        groups.append({"key": key, "label": label, "images": images})
    all_images.sort(key=lambda x: x["mtime"], reverse=True)
    return groups, all_images


@app.route('/qualimatrix')
def qualimatrix():
    groups, all_images = collect_qualimatrix_data()
    return render_template('qualimatrix.html',
                           diagram_groups=groups,
                           all_images=all_images)

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
