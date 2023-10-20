from .models import db, User
from .models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token
import jwt
import time

secret_key = "secret_key"


def validate_user_token(token):
    code_record = OAuth2Token.query.filter_by(jwt_token=token).first()
    if code_record:
        return True
    else:
        return False


def validate_user_authcode(code):
    code_record = OAuth2AuthorizationCode.query.filter_by(
        authcode=code).first()
    if code_record and code_record.expires_at > int(time.time()):
        return True
    else:
        # The record doesn't exist or is expired
        return False



def store_user_authcode(user, code, scope_string):
    print(f"scope sting in auth code creation: {scope_string}")
    auth_code = OAuth2AuthorizationCode(
        user_id=user,
        authcode=code,
        scope=scope_string,
        expires_at=int(time.time()) + 300
    )
    db.session.add(auth_code)
    db.session.commit()


def create_token(code):
    # Initialize token to None
    token = None

    # Validate the auth code
    if validate_user_authcode(code):
        # Get the user ID from the auth code
        user_id = get_user_from_code(code)

        code_record = OAuth2AuthorizationCode.query.filter_by(
            authcode=code).first()
        scope_string = code_record.scope

        # Issue the JWT
        token = issue_jwt(scope_string, user_id)

        # Store the token in the database
        store_user_token(code, token)
    else:
        # Handle the case where validation fails
        print("Validation failed for the provided code.")

    return token


def delete_token(code):
    code_record = OAuth2Token.query.filter_by(jwt_token=code).first()
    if (code_record):
        # delete
        db.session.delete(code_record)
        return True
    else:
        return False
        # return false


def issue_jwt(scope_string, id):
    iss_at = int(time.time())
    time_exp = int(time.time()) + 86400

    scope = scope_string.split(",")
    print(f"scope string: {scope_string} turned into scope: {scope}")
    # Define the claims (payload) of the JWT
    claims = {
        'issued_at': iss_at,
        'exp': time_exp,  # Expiration time
        'scope': scope,  # Scope
        'token_type': "Bearer",
        "iss": "Himalia",
        "id": id
    }

    jwt_token = jwt.encode(claims, secret_key, algorithm='HS256')
    return jwt_token


def get_user_from_code(code):
    code_record = OAuth2AuthorizationCode.query.filter_by(
        authcode=code).first()
    if code_record:
        # The record exists, you can access its attributes
        return code_record.user_id
    # Access other attributes as needed
    else:
        # The record doesn't exist
        return 0


def store_user_token(code, token):
    # get user
    user = get_user_from_code(code)
    # Create a new UserToken instance
    user_token = OAuth2Token(user_id=user, jwt_token=token)
    # Add the UserToken instance to the session and commit the transaction
    db.session.add(user_token)
    db.session.commit()
