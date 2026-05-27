import os
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, redirect, render_template, request, send_from_directory, session, url_for, flash
from werkzeug.utils import secure_filename

from app.db import get_db_connection
from app.services.storage import DIAGRAM_BASE, DIAGRAM_TYPES, allowed_file, save_uploaded_file

public_bp = Blueprint('public', __name__)

@public_bp.route('/')
@public_bp.route('/landing')
def landing():
    conn = get_db_connection()
    today = datetime.today().date()
    announcements = conn.execute('SELECT * FROM announcements WHERE expires_at IS NULL OR date(expires_at) >= ? ORDER BY created_at DESC', (today,)).fetchall()
    conn.close()
    return render_template('landing.html', announcements=announcements)

@public_bp.route('/anzeige')
def anzeigen():
    timestamp = int(datetime.now().timestamp())
    screenshot_path = request.args.get('image', 'screenshots/screenshot.png')
    return render_template('anzeigen.html', timestamp=timestamp, screenshot_path=screenshot_path)

@public_bp.route('/uploads/<path:filename>')
def uploaded_file(filename):
    from flask import current_app
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

@public_bp.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not file.filename:
            flash('Bitte eine Datei auswählen.')
            return redirect(url_for('public.upload'))
        try:
            screenshot_path = save_uploaded_file(file, 'screenshots')
        except ValueError as exc:
            flash(f'Upload fehlgeschlagen: {exc}')
            return redirect(url_for('public.upload'))
        return redirect(url_for('public.anzeigen', image=screenshot_path))
    return render_template('upload.html')

@public_bp.route('/api/announcements')
def api_announcements():
    conn = get_db_connection()
    today = datetime.today().date()
    rows = conn.execute('SELECT id, title, content, source, attachment_path FROM announcements WHERE expires_at IS NULL OR date(expires_at) >= ? ORDER BY created_at DESC', (today,)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@public_bp.route('/schulungen')
def schulungen():
    conn = get_db_connection()
    all_trainings = conn.execute('SELECT * FROM trainings ORDER BY date ASC').fetchall()
    today = datetime.today().date()
    in_30_days = (today + timedelta(days=30)).isoformat()
    upcoming = conn.execute('SELECT * FROM trainings WHERE date BETWEEN ? AND ? ORDER BY date ASC', (today.isoformat(), in_30_days)).fetchall()
    conn.close()
    return render_template('trainings.html', trainings=all_trainings, upcoming=upcoming)

@public_bp.route('/api/trainings')
def api_trainings():
    conn = get_db_connection()
    rows = conn.execute("""SELECT * FROM trainings WHERE date > DATE('now') OR (date = DATE('now') AND (time IS NULL OR time >= TIME('now'))) ORDER BY date ASC, time ASC""").fetchall()
    conn.close()
    events = []
    for row in rows:
        title = row['title'] + (f" ({row['time']})" if row['time'] else '')
        events.append({'title': title, 'start': row['date'], 'allDay': True, 'extendedProps': {'participants': row['participants'] or ''}})
    return jsonify(events)

@public_bp.route('/api/trainings/upcoming')
def api_upcoming_trainings():
    conn = get_db_connection()
    rows = conn.execute("""SELECT * FROM trainings WHERE date BETWEEN DATE('now') AND DATE('now', '+30 day') ORDER BY date ASC, time ASC""").fetchall()
    conn.close()
    upcoming = []
    for row in rows:
        participants = (row['participants'] or '').strip()
        participant_list = [p.strip() for p in participants.split(',') if p.strip()]
        upcoming.append({
            'date': row['date'],
            'title': row['title'],
            'time': row['time'],
            'participants': participant_list
        })
    return jsonify(upcoming)

@public_bp.route('/qualimatrix')
def qualimatrix():
    from flask import url_for
    groups, all_images = [], []
    for key, label in DIAGRAM_TYPES.items():
        folder = os.path.join(DIAGRAM_BASE, key)
        images = []
        if os.path.isdir(folder):
            files = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f)) and allowed_file(f)]
            files.sort(key=lambda n: os.path.getmtime(os.path.join(folder, n)), reverse=True)
            for name in files:
                path = os.path.join(folder, name)
                item = {'src': url_for('static', filename=f'diagramme/ausschussquote/{key}/{name}'), 'name': name, 'mtime': os.path.getmtime(path), 'key': key, 'label': label}
                images.append(item)
                all_images.append(item)
        groups.append({'key': key, 'label': label, 'images': images})
    all_images.sort(key=lambda x: x['mtime'], reverse=True)
    return render_template('qualimatrix.html', diagram_groups=groups, all_images=all_images)

@public_bp.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
