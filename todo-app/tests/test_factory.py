from todoing import create_app
from todoing.main import is_checked
from flask import Flask, g, session
from flask.testing import FlaskClient


def test_config():
    assert not create_app().testing
    assert create_app({'TESTING': True}).testing

def test_index_route_without_user(client):
    response = client.get('/')
    assert response.status_code == 200

def test_create_route(client):
    response = client.get('/create')
    assert response.status_code == 302  # Redirect when not logged in

    # Simulate a logged-in user
    with client.session_transaction() as session:
        session['user_id'] = 1

    response = client.get('/create')
    assert response.status_code == 200


def test_update_route(client):
    response = client.get('/1/update')
    assert response.status_code == 302  # Redirect when not logged in

    # Simulate a logged-in user
    with client.session_transaction() as session:
        session['user_id'] = 1

    response = client.get('/1/update')
    assert response.status_code == 200

def test_delete_route(client):
    response = client.post('/1/delete')
    assert response.status_code == 302  # Redirect when not logged in

    # Simulate a logged-in user
    with client.session_transaction() as session:
        session['user_id'] = 1

    response = client.post('/1/delete')
    assert response.status_code == 302  # Redirect after deletion

def test_index_route_with_user(client, monkeypatch):
    # Simulate a logged-in user by setting the session user id
    with client.session_transaction() as session:
        session['user_id'] = 1

    response = client.get('/')
    assert response.status_code == 200


def test_create_route_post_invalid_title(client):
    # Simulate a logged-in user session
    with client.session_transaction() as session:
        session['user_id'] = 1

    response = client.post('/create', data={'title': ''})
    assert response.status_code == 200
    

def test_create_route_post_valid_title(client):
    # Simulate a logged-in user session
    with client.session_transaction() as session:
        session['user_id'] = 1

    response = client.post('/create', data={'title': 'Test Todo'})
    assert response.status_code == 302  # Redirect after successful post

    # Ensure the response is redirected to the index page
    assert response.location.endswith('/')

def test_update_route_post_invalid_title(client):
    # Simulate a logged-in user session
    with client.session_transaction() as session:
        session['user_id'] = 1

    response = client.post('/1/update', data={'title': ''})  # Replace '1' with an actual todo ID
    assert response.status_code == 200
    assert b'Title is required.' in response.data

def test_update_route_post_valid_title(client):
    # Simulate a logged-in user session
    with client.session_transaction() as session:
        session['user_id'] = 1

    response = client.post('/1/update', data={'title': 'Updated Todo'})  # Replace '1' with an actual todo ID
    assert response.status_code == 302  # Redirect after successful post

    # Ensure the response is redirected to the index page
    assert response.location.endswith('/')    
