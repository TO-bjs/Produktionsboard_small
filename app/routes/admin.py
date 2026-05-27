import os
import uuid

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from app.db import get_db_connection
from app.services.storage import DIAGRAM_BASE, DIAGRAM_TYPES, allowed_file, save_uploaded_file

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    if not session.get('is_admin'):
        return redirect(url_for('auth.login'))
    conn = get_db_connection()
    if request.method == 'POST':
        if 'delete' in request.form:
            conn.execute('DELETE FROM users WHERE id = ?', (request.form['delete'],))
        else:
            conn.execute('INSERT INTO users (username, password_hash, email, is_admin) VALUES (?, ?, ?, ?)',
                         (request.form['new_username'], generate_password_hash(request.form['new_password']), request.form['new_email'], 1 if 'new_admin' in request.form else 0))
        conn.commit()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

@admin_bp.route('/update_user', methods=['POST'])
def update_user():
    if not session.get('is_admin'):
        return redirect(url_for('auth.login'))
    user_id = request.form['user_id']
    email = request.form['email']
    is_admin = int(request.form.get('is_admin', 0))
    new_password = request.form.get('new_password', '')
    conn = get_db_connection()
    if new_password:
        conn.execute('UPDATE users SET email = ?, is_admin = ?, password_hash = ? WHERE id = ?', (email, is_admin, generate_password_hash(new_password), user_id))
    else:
        conn.execute('UPDATE users SET email = ?, is_admin = ? WHERE id = ?', (email, is_admin, user_id))
    conn.commit(); conn.close()
    flash('Benutzer erfolgreich aktualisiert.')
    return redirect(url_for('admin.admin_users'))

@admin_bp.route('/admin/ankuendigung', methods=['GET', 'POST'])
def manage_announcements():
    if not session.get('is_admin'):
        return redirect(url_for('auth.login'))
    conn = get_db_connection()
    if request.method == 'POST':
        if 'delete_id' in request.form:
            conn.execute('DELETE FROM announcements WHERE id = ?', (request.form['delete_id'],))
            conn.commit(); conn.close()
            return redirect(url_for('admin.manage_announcements'))

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
                flash('Ungültiger Dateityp. Erlaubt sind nur Bilddateien.')
                conn.close()
                return redirect(url_for('admin.manage_announcements'))
        conn.execute('INSERT INTO announcements (title, content, source, attachment_path, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?)',
                     (title, content, source, attachment_path, expires_at, session.get('user_id')))
        conn.commit()
    announcements = conn.execute('SELECT * FROM announcements ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('manage_announcements.html', announcements=announcements)

@admin_bp.route('/admin/trainings', methods=['GET', 'POST'])
def admin_trainings():
    if not session.get('is_admin'):
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        conn = get_db_connection()
        conn.execute('INSERT INTO trainings (title, date, time, participants) VALUES (?, ?, ?, ?)', (request.form['title'], request.form['date'], request.form.get('time'), request.form.get('participants')))
        conn.commit(); conn.close()
        flash('Schulung erfolgreich hinzugefügt.')
        return redirect(url_for('admin.admin_trainings'))
    conn = get_db_connection()
    trainings = conn.execute('SELECT * FROM trainings ORDER BY date DESC, time DESC').fetchall()
    conn.close()
    return render_template('admin_trainings.html', trainings=trainings)

@admin_bp.route('/admin/trainings/<int:tid>/delete', methods=['POST'])
def admin_trainings_delete(tid):
    if not session.get('is_admin'):
        return redirect(url_for('auth.login'))
    conn = get_db_connection(); conn.execute('DELETE FROM trainings WHERE id = ?', (tid,)); conn.commit(); conn.close()
    flash('Schulung gelöscht.')
    return redirect(url_for('admin.admin_trainings'))

@admin_bp.route('/admin/upload_qualimatrix', methods=['GET', 'POST'])
def upload_qualimatrix():
    if not session.get('is_admin'):
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        updated = []
        for key, label in DIAGRAM_TYPES.items():
            files = [f for f in request.files.getlist(key) if f and f.filename]
            if not files:
                continue
            target_dir = os.path.join(DIAGRAM_BASE, key)
            for name in os.listdir(target_dir):
                try: os.remove(os.path.join(target_dir, name))
                except Exception: pass
            invalid_files = []
            for f in files:
                safe_name = secure_filename(f.filename)
                if not allowed_file(safe_name):
                    invalid_files.append(f.filename); continue
                ext = safe_name.rsplit('.', 1)[1].lower()
                f.save(os.path.join(target_dir, f"{uuid.uuid4().hex}.{ext}"))
            if invalid_files:
                flash(f"Ungültiger Dateityp in {label}: {', '.join(invalid_files)}. Erlaubt sind nur Bilddateien.")
                return redirect(url_for('admin.upload_qualimatrix'))
            updated.append(label)
        flash(f"Upload erfolgreich für: {', '.join(updated)}" if updated else 'Keine Dateien ausgewählt.')
        return redirect(url_for('admin.upload_qualimatrix'))
    return render_template('upload_qualimatrix.html', diagram_types=DIAGRAM_TYPES)
