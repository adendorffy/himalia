import os
import tempfile

'''
 The purpose of this file is to set up testing fixtures and actions that facilitate the testing of various functionalities of the application in an isolated and controlled environment.

'''

## Imports for the testing using Pytest
import pytest
from todoing import create_app
from todoing.db import get_db, init_db

#This decodes the data.sql database and makes it into a file _data_sql
with open(os.path.join(os.path.dirname(__file__), 'data.sql'), 'rb') as f:
    _data_sql = f.read().decode('utf8')

# This a class that holds the objects for testing login and logout
class AuthActions(object):
    def __init__(self, client):
        self._client = client

    def login(self, username='test', password='test'):
        return self._client.post(
            '/auth/login',
            data={'username': username, 'password': password}
        )

    def logout(self):
        return self._client.get('/auth/logout')

## A fixture is a test essentially 
# This fixture defines a set of actions related to authentication for testing
# returns an object
@pytest.fixture
def auth(client):
    return AuthActions(client)    

# This fixture sets up the testing environment by creating a temporary database and app
@pytest.fixture
def app():
    # Create a temporary database file and get its file descriptor and path
    db_fd, db_path = tempfile.mkstemp()

     # Create a testing app with specific configurations
    app = create_app({
        'TESTING': True,
        'DATABASE': db_path,
    })

    # Initialize the database and execute SQL script from the todoing app
    with app.app_context():
        init_db()
        get_db().executescript(_data_sql)

    yield app

    # Clean up by closing the file descriptor and removing the temporary database file
    os.close(db_fd)
    os.unlink(db_path)    

# This fixture provides a testing client for making HTTP requests to the app
@pytest.fixture
def client(app):
    return app.test_client()

# This fixture provides a testing runner for invoking CLI commands on the app
@pytest.fixture
def runner(app):
    return app.test_cli_runner()    