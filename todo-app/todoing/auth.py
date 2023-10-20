import functools
import re
from flask import (
    Flask, Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash
from todoing.db import get_db

from authlib.integrations.flask_client import OAuth
import os
import requests
import bcrypt
import jwt

# Create a blueprint named 'auth' with the URL prefix '/auth'
bp = Blueprint('auth', __name__, url_prefix='/auth')
app = Flask(__name__)
app.secret_key = os.urandom(12)
oauth = OAuth(app)

# Initialize OAuth client once during app setup
GOOGLE_CLIENT_ID = '241734704350-f5sv2m3vi8n9s924kviishbd01lffbgk.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'

CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Route for user registration


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None
        salt = bcrypt.gensalt()

        # Validate username and password
        # Use regex to validate the email address
        if not_valid_email(email):
            error = "Email is invalid."
        if not email:
            error = 'Email address is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                # Insert user information into the database
                db.execute(
                    "INSERT INTO user (email, user_type) VALUES (?, ?)",
                    (email, "native"),
                )
                print("User created")
                db.commit()
                user = db.execute(
                    'SELECT * FROM user WHERE email = ?', (email,)
                ).fetchone()

                print("User fetched")
                if user is None:
                    error = "User not found"

                db.execute(
                    "INSERT INTO password (user_id, password, salt) VALUES (?, ?, ?)",
                    (user['id'], generate_password_hash(salt.decode(
                        'utf-8') + password), salt.decode('utf-8')),
                )
                print("User password created")
                db.commit()
            except db.IntegrityError:
                error = f"User {email} is already registered."
            else:
                session.clear()
                session['user_id'] = user['id']
                return redirect(url_for("index"))

        flash(error)

    return render_template('auth/register.html')

# Route for user login


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None

        user = db.execute(
            'SELECT * FROM user WHERE email = ?', (email,)
        ).fetchone()  # This will retrieve all rows that match the query

        if user is None:
            error = "User not found"
            return redirect(url_for("auth.register"))

        # Validate username and password
        if user['user_type'] == "native":
            password_hash = db.execute(
                "SELECT * FROM password WHERE user_id = ?", (user['id'],)).fetchone()
            print(password_hash)

            if not (check_password_hash(password_hash['password'], password_hash['salt'] + password)):
                error = 'Incorrect password'
            else:
                session.clear()
                session['user_id'] = user['id']
                return redirect(url_for("index"))

        elif user['user_type'] == "google":
            error = 'Sign in with Google'
        elif user['user_type'] == "himalia":
            error = 'Sign in with Himalia'

        if error is None:

            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

# Function to load the logged-in user before each request


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    error = None

    if user_id is None:
        g.user = None
    else:
        user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()  # This will retrieve all rows that match the query

        if user is None:
            error = "User not found"

        if error is None:
            g.user = user

# Route for user logout


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Decorator to require user login for certain views


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


def not_valid_email(email):
    pattern = r'^\S+@\S+\.\S+$'
    if re.match(pattern, email) is None:
        return True

    return False


@bp.route('/google/')
def google():
    """Start the OAuth process."""
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@bp.route('/google/callback')
def google_callback():
    """Handle the callback after user gives consent."""
    token = oauth.google.authorize_access_token()
    email = token['userinfo']['email']
    db = get_db()

    # Check if user exists in the 'user' table
    user = db.execute(
        "SELECT * FROM user WHERE email = ? AND user_type = ?", (email, "google")).fetchone()
    if user is not None:
        # Log the user in
        session.clear()
        session['user_id'] = user['id']
        return redirect(url_for('index'))

    if user is None:
        try:
            # Register new user
            db.execute(
                "INSERT INTO user (email, user_type) VALUES (?, ?)", (email, "google"))
            db.commit()

            user_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        except db.IntegrityError:
            error = f"User {email} is already registered with another account."
            flash(error)
            return redirect(url_for("auth.login"))

        user = db.execute("SELECT * FROM user WHERE id = ?",
                          (user_id,)).fetchone()
        if user is None:
            error = "User not found"
            flash(error)
            return redirect(url_for("auth.login"))

    # Log the user in
    session.clear()
    session['user_id'] = user['id']

    return redirect(url_for('index'))


@bp.route('/google_login')
def google_login():
    # Redirect to google function
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@bp.route('/himalia_login')
def himalia_login():
    redirect_uri = "http://127.0.0.1:5000/authorize/Todoing"
    return redirect(redirect_uri)


@bp.route('/himalia/callback')
def himalia_callback():
    error_message = request.args.get('error')
    if error_message:

        flash(error_message)
        print(f"Error: {error_message}")
        # Display or handle the error message as needed
        return redirect(url_for('auth.login'))
    auth_code = request.args.get('code')
    if auth_code:
        data = {'code': auth_code}
        response = requests.post(
            'http://127.0.0.1:5000/oauth/token', data=data)

        if response.status_code == 200:
            token = response.json()
            access_token = token['access_token']

            # Assuming your Flask app is running on port 5000
            url = "http://127.0.0.1:5000/userinfo"
            headers = {
                "Authorization": f"Bearer {access_token}"
            }
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                print(f"data: {data}")
                if data.get('error'):
                    if data.get('error') == 'Invalid scope':
                        flash('You have to consent to your email')
                        return redirect(url_for("auth.login"))
                    flash('Error fetching user information')
                    return redirect(url_for("auth.login"))
                email = data.get('user_email')
                if email is None:
                    flash("You have to consent to your email")
                    return redirect(url_for("auth.login"))
                db = get_db()

                # Check if the user with the given email and provider exists in the 'user' table
                user = db.execute(
                    "SELECT * FROM user WHERE email = ? ", (email,)).fetchone()
                if user is None:
                    # Insert the new user into the 'user' table
                    db.execute(
                        "INSERT INTO user (email, user_type) VALUES (?, ?)", (email, "himalia"))
                    db.commit()

                    # Get the last inserted user ID
                    user_id = db.execute(
                        "SELECT last_insert_rowid()").fetchone()[0]

                    # Insert the OAuth-specific information into the 'oauth_user' table
                    token = jwt.decode(
                        token['access_token'], "secret_key", algorithms=['HS256'])

                    user = db.execute(
                        "SELECT * FROM user WHERE email = ? AND user_type = ?", (email, "himalia")).fetchone()
                    if user is None:
                        error = "User not found"
                        flash(error)
                        return redirect(url_for("auth.login"))
                    print("User created")
                    session.clear()
                    session['user_id'] = user['id']

                else:
                    print("User already exists")
                    if user['user_type'] == "native":
                        flash("Log in with username and password")
                        return redirect(url_for("auth.login"))

                    elif user['user_type'] == "himalia":
                        session.clear()
                        session['user_id'] = user['id']
                        print(f"{user['email']} logged in")
                        return redirect(url_for('index'))
                    else:
                        flash("Log in with Google")
                        return redirect(url_for("auth.login"))
            else:

                flash("Error fetching user information")
                return redirect(url_for("auth.login"))
    return redirect(url_for("index"))


@bp.route('/delete_user', methods=["POST"])
def delete_user():
    if not g.user:
        flash("Not logged in!")
        return redirect(url_for('index'))

    # Assuming the logged-in user information has an 'id' field
    user_id = g.user['id']
    # Database operation to delete the user
    get_db().execute("DELETE FROM user WHERE id = ?", (user_id,))
    get_db().commit()
    if get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone() is None:
        print(f"User deleted successfuly")
    flash("User deleted successfully.")
    return redirect(url_for('auth.logout'))
