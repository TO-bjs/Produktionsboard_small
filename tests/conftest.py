import sqlite3
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from app.db import init_db


@pytest.fixture()
def app_instance(tmp_path):
    db_path = tmp_path / 'test_users.db'
    app = create_app('testing')
    app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'DATABASE': str(db_path),
    })
    with app.app_context():
        init_db()
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                'INSERT INTO users (username, password_hash, email, is_admin) VALUES (?, ?, ?, ?)',
                ('admin', generate_password_hash('adminpw'), 'admin@example.com', 1),
            )
            conn.execute(
                'INSERT INTO users (username, password_hash, email, is_admin) VALUES (?, ?, ?, ?)',
                ('user', generate_password_hash('userpw'), 'user@example.com', 0),
            )
            conn.commit()
    yield app


@pytest.fixture()
def client(app_instance):
    return app_instance.test_client()
