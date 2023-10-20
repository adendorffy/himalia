import pytest
from flask import g, session
from todoing.db import get_db

# Tests the register functionality by simulating a post request
def test_register(client, app):
    assert client.get('/auth/register').status_code == 200
    response = client.post(
        '/auth/register', data={'username': 'a', 'password': 'a'}
    )
# Checks the header for correct redirect to login
    assert response.headers["Location"] == "/auth/login"
#CHecks the database for correct insertion of posted content
    with app.app_context():
        assert get_db().execute(
            "SELECT * FROM user WHERE username = 'a'",
        ).fetchone() is not None

#THis sets up the content that eill be passed to the app
@pytest.mark.parametrize(('username', 'password', 'message'), (
    ('', '', b'Username is required.'),
    ('a', '', b'Password is required.'),
    ('test', 'test', b'already registered'),
))
#Posts the data and checks various combinations and extpects a message
def test_register_validate_input(client, username, password, message):
    response = client.post(
        '/auth/register',
        data={'username': username, 'password': password}
    )
    #if message is correct it asserts true
    assert message in response.data

# check logins and redirects from logins
def test_login(client, auth):
    assert client.get('/auth/login').status_code == 200
    response = auth.login()
    assert response.headers["Location"] == "/"

    with client:
        client.get('/')
        assert session['user_id'] == 1
        assert g.user['username'] == 'test'

#Sets up testing data
@pytest.mark.parametrize(('username', 'password', 'message'), (
    ('a', 'test', b'Incorrect username.'),
    ('test', 'a', b'Incorrect password.'),
))
## passes the data to the fucntion and expects message
def test_login_validate_input(auth, username, password, message):
    response = auth.login(username, password)
    # asserts for correct messages
    assert message in response.data    

def test_logout(client, auth):
    auth.login()

    with client:
        auth.logout()
        ## if user is not in session anymore we sucessdully logout 
        assert 'user_id' not in session