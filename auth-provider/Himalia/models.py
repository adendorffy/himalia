import time
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))  # Name of the user
    email = db.Column(db.String(100), unique=True)  # Email address
    username = db.Column(db.String(40), unique=True)
    password = db.Column(db.String(255))  # Hashed password

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if 'password' in kwargs:
            self.password = generate_password_hash(
                kwargs['password'], method='scrypt')

    def __str__(self):
        return self.username

    def get_user_id(self):
        return self.id

    def check_password(self, password):

        # Verify if the hashed version of the provided password matches the stored hashed password
        return check_password_hash(self.password, password)

    # Getter function for email
    def get_email(self):
        return self.email

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class OAuth2Client(db.Model):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    # Removing user_id and user relationship
    # This might be better named as 'client_name' now
    username = db.Column(db.String(24))
    client_id = db.Column(db.String(24), unique=True)
    client_uri = db.Column(db.String(200))
    secret_id = db.Column(db.String(24), unique=True)
    redirect_uri = db.Column(db.String(200))  # Added redirect_uri

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class OAuth2AuthorizationCode(db.Model):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')
    authcode = db.Column(db.String(24), unique=True)
    # New field for storing authorized scopes
    scope = db.Column(db.String(255))
    expires_at = db.Column(db.Integer)  # New field for storing expiration time

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class OAuth2Token(db.Model):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')
    jwt_token = db.Column(db.String(500))
