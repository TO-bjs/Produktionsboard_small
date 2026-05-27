import sqlite3
from flask import current_app


def init_db():
    with sqlite3.connect(current_app.config['DATABASE']) as conn:
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


def get_db_connection():
    conn = sqlite3.connect(current_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn
