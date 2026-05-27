import sqlite3


def _login_admin(client):
    return client.post('/login', data={'username': 'admin', 'password': 'adminpw'}, follow_redirects=True)


def test_admin_can_create_user(client, app_instance):
    _login_admin(client)
    response = client.post(
        '/admin/users',
        data={
            'new_username': 'newuser',
            'new_password': 'newpw',
            'new_email': 'new@example.com',
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    with sqlite3.connect(app_instance.config['DATABASE']) as conn:
        count = conn.execute("SELECT COUNT(*) FROM users WHERE username = 'newuser'").fetchone()[0]
    assert count == 1


def test_admin_can_delete_user(client, app_instance):
    _login_admin(client)
    with sqlite3.connect(app_instance.config['DATABASE']) as conn:
        user_id = conn.execute("SELECT id FROM users WHERE username = 'user'").fetchone()[0]
    response = client.post('/admin/users', data={'delete': str(user_id)}, follow_redirects=True)
    assert response.status_code == 200
    with sqlite3.connect(app_instance.config['DATABASE']) as conn:
        count = conn.execute("SELECT COUNT(*) FROM users WHERE id = ?", (user_id,)).fetchone()[0]
    assert count == 0
