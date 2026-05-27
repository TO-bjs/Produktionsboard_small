def test_login_success(client):
    response = client.post('/login', data={'username': 'user', 'password': 'userpw'}, follow_redirects=False)
    assert response.status_code == 302
    assert '/landing' in response.headers['Location']


def test_reset_request_always_returns_ok(client):
    response = client.post('/reset', data={'email': 'user@example.com'}, follow_redirects=True)
    assert response.status_code == 200
    assert 'Wenn die E-Mail existiert'.encode() in response.data
