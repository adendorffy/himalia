import time
import uuid
from flask import Blueprint, current_app, flash, request, session, url_for
from flask import render_template, redirect, jsonify, request
import jwt
from werkzeug.security import gen_salt, generate_password_hash
from .models import OAuth2AuthorizationCode, OAuth2Token, db, User, OAuth2Client
from .oauth2 import create_token, delete_token, store_user_authcode
bp = Blueprint('home', __name__)


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@bp.route('/', methods=('GET', 'POST'))
def home():
    clients = OAuth2Client.query.all()
    users = User.query.all()
    return render_template('home.html', clients=clients, users=users)


@bp.route('/client/<int:client_id>', methods=["GET"])
def client_info(client_id):
    client = OAuth2Client.query.get(client_id)
    if not client:
        return "Client not found", 404
    return render_template('client_info.html', client=client)


@bp.route('/user/<int:user_id>', methods=["GET"])
def get_user_info(user_id):

    user = User.query.get(user_id)
    if not user:
        return "User not found", 404
    return render_template('user_info.html', user=user)


@bp.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        # Theres a user that is added here , you can modify to add several users
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        # if user is not just to log in, but need to head back to the auth page, then go for it
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect('/')


@bp.route('/create_user', methods=['POST', 'GET'])
def create_user():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another.', 'danger')
            return redirect(url_for('home.create_user'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please choose another.', 'danger')
            return redirect(url_for('home.create_user'))

        new_user = User(name=name, email=email,
                        username=username, password=password)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('home.home'))

    return render_template('create_user.html')


@bp.route('/delete_user/<int:user_id>', methods=('POST',))
def delete_user(user_id):

    try:
        user = User.query.get(user_id)
        if not user:
            print(f"No user found with ID: {user_id}")
        else:
            print(f"Found user with ID: {user_id}")
            user.delete()
    except Exception as e:
        print(f"Error querying database: {e}")
    # You can flash a message or log the deletion here if needed.
    return redirect('/')


@bp.route('/create_client', methods=('GET', 'POST'))
def create_client():

    # If GET request, render the form template
    if request.method == 'GET':
        # Assuming your form is in 'client_form.html'
        return render_template('create_client.html')

    # If POST request, process form data
    client_id = gen_salt(24)
    secret = gen_salt(24)
    client_name = request.form.get('client_name')
    client_uri = request.form.get('client_uri')
    redirect_uri = request.form.get('redirect_uri')

    # You might need to process token_endpoint_auth_method too if it affects client creation

    client = OAuth2Client(
        client_id=client_id,
        username=client_name,  # Assuming 'username' is synonymous with 'client_name'
        client_uri=client_uri,
        secret_id=secret,
        redirect_uri=redirect_uri  # Assuming you've added this column to the OAuth2Client model
    )
    existing_client = OAuth2Client.query.filter_by(
        username=client_name).first()
    if existing_client:
        flash('Client ID already exists. Please choose another.', 'danger')
        return redirect(url_for('home.create_client'))

    print(f"client added: {client_name}")
    db.session.add(client)
    db.session.commit()

    return redirect('/')


@bp.route('/delete_client/<int:client_id>', methods=('POST',))
def delete_client(client_id):

    try:
        client = OAuth2Client.query.get(client_id)
        if not client:
            print(f"No client found with ID: {client_id}")
        else:
            print(f"Found client with ID: {client.id}")
            client.delete()
    except Exception as e:
        print(f"Error querying database: {e}")
    # You can flash a message or log the deletion here if needed.
    return redirect('/')


def authenticate_user(email, password):
    print("Authenticate user")
    if password is None:
        return None
    user = User.query.filter_by(email=email).first()
    print(f"user: {user.password}")
    if user.check_password(password):
        print("passwords match")
        return user
    else:
        return None


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    # access route with client_id , client_secret and token
    token = create_token(request.form.get('code'))
    return {"access_token": token}


@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    if (delete_token(request.form.get('code'))):
        return "Token deleted"
    else:
        return "Token not deleted"


@bp.route('/userinfo', methods=['GET'])
def user_info():
    token = request.headers.get('Authorization').replace('Bearer ', '')
    user_info = get_user_from_token(token)
    if user_info:
        print(f"User info: {user_info}")
        return jsonify(user_info)  # Return required user data
    return jsonify(error='Invalid token'), 401


def decode_token(token):
    # Decode the token
    secret_key = "secret_key"
    return jwt.decode(token, secret_key, algorithms=['HS256'])


def delete_token_entry(token_entry):
    db.session.delete(token_entry)
    db.session.commit()


def fetch_user(user_id):
    return User.query.get(user_id)


def extract_user_info(payload, scope_mappings, user):
    user_info = {}
    scope = payload.get('scope')
    # Extract the user information
    email = user.email
    name = user.name
    username = user.username
    for s in scope:
        if s in scope_mappings:
            user_info[s] = locals()[scope_mappings[s]]
    return user_info


def get_user_from_token(token):
    try:
        payload = decode_token(token)
        print(payload)

        token_entry = OAuth2Token.query.filter_by(jwt_token=token).first()

        if not token_entry:
            return {'error': 'Token expired'}

        # delete_token_entry(token_entry)
        user_id = token_entry.user_id

        if not user_id:
            return {'error': 'Invalid token'}

        user = fetch_user(user_id)

        if not user:
            return {'error': 'User doesn\'t exist'}

        print(f"user: {user}")

        scope_mappings = {
            'user_email': 'email',
            'user_name': 'name',
            'user_username': 'username',
        }

        user_info = extract_user_info(payload, scope_mappings, user)
        scope = payload.get('scope')
        if not user_info or len(user_info) != len(scope):
            return {'error': 'Invalid scope'}

        return user_info

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


@bp.route("/authorize/<client_username>", methods=["GET", "POST"])
def request_auth(client_username):
    # Clear the session at the beginning of the function
    session.clear()

    client = OAuth2Client.query.filter_by(username=client_username).first()
    if client is None:
        return redirect_with_error(client, "Client not registered for OAuth with Himalia")

    if request.method == "POST":
        return handle_user_login(client)
    else:
        return handle_get_request(client)


def handle_user_login(client):
    email, password = extract_user_data()
    user = authenticate_user(email, password)
    if user:
        # If the user is authenticated, store their ID in the session
        session['user_id'] = user.id
        return redirect(url_for('home.consent', client_username=client.username))
    else:
        return redirect_with_error(client, "Invalid email or password")


@bp.route("/consent/<client_username>", methods=["GET", "POST"])
def consent(client_username):
    print(request.method)
    client = OAuth2Client.query.filter_by(username=client_username).first()
    if request.method == "POST":
        return handle_post_request(client)
    else:
        user_id = session['user_id']
        user = User.query.get(user_id)
        print(f"User: {user.username}")
        print(f"Client: {client}")
        return render_template("consent.html", client=client, user=user)


def handle_post_request(client):
    # Check if the user is authenticated (user ID is in the session)
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            email_consent, name_consent, username_consent, final_submit = extract_consent_data()

            scope_values = build_scope_values(
                email_consent, username_consent, name_consent)
            scopes_string = ','.join(scope_values)

            auth_code = generate_auth_code()
            store_user_authcode(user.id, auth_code, scopes_string)
            return redirect(f"{client.redirect_uri}?code={auth_code}")

    # If the user is not authenticated or there was an issue, handle it here
    return redirect_with_error(client, "Authentication failed")


def handle_get_request(client):
    # Check if the user is authenticated (user ID is in the session)
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            return render_template("consent.html", client=client, user=user)

    # If the user is not authenticated, show the login page
    return render_template("authorize.html", client=client)


def extract_user_data():
    email = request.form.get('email')
    password = request.form.get('password')
    return email, password,


def extract_consent_data():
    email_consent = request.form.get('consent-email') == 'yes'
    name_consent = request.form.get('consent-name') == 'yes'
    username_consent = request.form.get('consent-username') == 'yes'
    final_submit = request.form.get('submit') == 'yes'
    return email_consent, name_consent, username_consent, final_submit


def build_scope_values(email_consent, username_consent, name_consent):
    scope_values = []
    if email_consent:
        scope_values.append('user_email')
    if username_consent:
        scope_values.append('user_username')
    if name_consent:
        scope_values.append('user_name')
    return scope_values


def generate_auth_code():
    return str(uuid.uuid4())


def redirect_with_error(client, error_message):
    return redirect(f"{client.redirect_uri}?error={error_message}")
