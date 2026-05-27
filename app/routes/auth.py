import secrets
from datetime import datetime, timedelta

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db_connection
from app.services.mail import send_email

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
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
            return redirect(url_for('public.landing'))
        flash('Login fehlgeschlagen.')
    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('public.landing'))


@auth_bp.route('/reset', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user:
            conn.execute('DELETE FROM reset_tokens WHERE user_id = ?', (user['id'],))
            token = secrets.token_urlsafe(32)
            expires = datetime.now() + timedelta(minutes=10)
            conn.execute('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)', (user['id'], token, expires.isoformat()))
            conn.commit()
            reset_link = f'http://produktion.to-labsystems.de/reset/{token}'
            subject = 'Passwort zurücksetzen'
            body = f"""Klicke auf den folgenden Link, um dein Passwort zurückzusetzen:
{reset_link}

Der Link ist 10 Minuten gültig."""
            send_email(subject, body, email)
        flash('Wenn die E-Mail existiert, wurde ein Link gesendet.')
    return render_template('reset_request.html')


@auth_bp.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    with get_db_connection() as conn:
        conn.execute('DELETE FROM reset_tokens WHERE expires_at < ?', (datetime.now(),))
        token_entry = conn.execute('SELECT * FROM reset_tokens WHERE token = ?', (token,)).fetchone()

    if not token_entry:
        flash('Token ist ungültig oder abgelaufen.')
        return redirect(url_for('auth.reset_request'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if not new_password:
            flash('Neues Passwort darf nicht leer sein.')
            return redirect(request.url)

        password_hash = generate_password_hash(new_password)
        with get_db_connection() as conn:
            conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, token_entry['user_id']))
            conn.execute('DELETE FROM reset_tokens WHERE user_id = ?', (token_entry['user_id'],))
            conn.commit()

        flash('Passwort erfolgreich geändert.')
        return redirect(url_for('auth.login'))

    return render_template('reset_token.html')
