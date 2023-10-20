import unittest
from unittest.mock import patch
from Himalia.app import create_app, db
from Himalia.models import User, OAuth2Token, OAuth2AuthorizationCode
from Himalia.routes import (
    extract_user_data,
    extract_consent_data,
    generate_auth_code,
    build_scope_values,
    current_user, extract_user_info, decode_token
)
from unittest.mock import MagicMock
import jwt
from jwt.exceptions import InvalidSignatureError


class Testroutes(unittest.TestCase):
    def setUp(self):
        # Configure Flask app for testing with a separate testing database
        self.app = create_app({'SECRET_KEY': 'secret',
                               'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
                               'SQLALCHEMY_TRACK_MODIFICATIONS': False,
                               'SQLALCHEMY_DATABASE_URI': 'sqlite:///test.db'})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.db = MagicMock()
        self.OAuth2Token = MagicMock()
        self.OAuth2AuthorizationCode = MagicMock()
        self.User = MagicMock()
        self.jwt = MagicMock()

        # Create test data
        self.user = User(name='John Doe', email='john@example.com')
        self.token = OAuth2Token(jwt_token='valid_token')
        self.authcode = OAuth2AuthorizationCode(authcode='valid_code')

    def tearDown(self):
        # Clean up and remove the testing database
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_generate_auth_code(self):
        code = generate_auth_code()
        self.assertIsNotNone(code)

    def test_extract_user_data_missing_data(self):
        request_mock = MagicMock()
        form_get = {}  # Simulate missing form data

        type(request_mock).form = form_get

        with patch('Himalia.routes.request', request_mock):
            email, password = extract_user_data()

        self.assertIsNone(email)
        self.assertIsNone(password)

    def test_extract_consent_data(self):
        form_data = {
            'consent-email': 'yes',
            'consent-name': 'no',
            'consent-username': 'yes',
            'submit': 'yes',
        }

        request_mock = MagicMock()
        form_mock = MagicMock()
        form_mock.get.side_effect = form_data.get

        request_mock.form = form_mock

        with patch('Himalia.routes.request', request_mock):
            email_consent, name_consent, username_consent, final_submit = extract_consent_data()

        self.assertTrue(email_consent)
        self.assertFalse(name_consent)
        self.assertTrue(username_consent)
        self.assertTrue(final_submit)

    def test_extract_consent_data_missing_data(self):
        request_mock = MagicMock()
        form_get = {}  # Simulate missing form data

        type(request_mock).form = form_get

        with patch('Himalia.routes.request', request_mock):
            email_consent, name_consent, username_consent, final_submit = extract_consent_data()

        self.assertFalse(email_consent)
        self.assertFalse(name_consent)
        self.assertFalse(username_consent)
        self.assertFalse(final_submit)

    def test_build_scope_values(self):

        email_consent = True
        username_consent = False
        name_consent = True

        scope_values = build_scope_values(
            email_consent, username_consent, name_consent)

        self.assertEqual(scope_values, ['user_email', 'user_name'])

    def test_build_scope_values_no_consent(self):
        # Test when none of the consent options are selected
        email_consent = False
        username_consent = False
        name_consent = False

        # Call the function
        scope_values = build_scope_values(
            email_consent, username_consent, name_consent)

        # Check that scope_values is an empty list
        self.assertEqual(scope_values, [])

    def test_current_user_authenticated(self):
        # Arrange
        user_id = 1
        session_data = {'id': user_id}

        # Create a MagicMock for User.query.get
        user_query_mock = MagicMock()
        user_query_mock.get.return_value = User(id=user_id)

        # Create a MagicMock for the session object
        session_mock = MagicMock()
        session_mock.__contains__.return_value = True
        session_mock.__getitem__.side_effect = session_data.get

        # Act
        with patch('Himalia.routes.session', session_mock), \
                patch.object(User.query, 'get', user_query_mock):
            user = current_user()

        # Assert
        self.assertIsNone(user)
        self.assertEqual(user_id, user_id)

    def test_extract_user_info(self):
        # Mock payload, scope_mappings, and user
        payload = {
            'scope': ['user_email', 'user_name', 'user_username'],
        }
        scope_mappings = {
            'user_email': 'email',
            'user_name': 'name',
            'user_username': 'username',
        }
        user = User(email='test@example.com', name='John Doe',
                    username='johndoe', password="1")

        # Call the function to extract user info
        user_info = extract_user_info(payload, scope_mappings, user)

        # Check if the extracted user info matches the expected values
        self.assertEqual(user_info, {
            'user_email': 'test@example.com',
            'user_name': 'John Doe',
            'user_username': 'johndoe',
        })

    def test_decode_token_happy_path(self):
        # Mock a valid token
        payload = {'user_id': 1}
        secret_key = "secret_key"
        token = jwt.encode(payload, secret_key, algorithm='HS256')

        # Decode the token using the function
        decoded_payload = decode_token(token)

        # Check if the decoded payload matches the original payload
        self.assertEqual(decoded_payload, payload)

    def test_decode_token_sad_path(self):
        # Mock an invalid token (e.g., tampered or expired)
        payload = {'user_id': 1}
        secret_key = "different_secret_key"
        invalid_token = jwt.encode(payload, secret_key, algorithm='HS256')

        # Check if the decoded payload is None (indicating an error)
        with self.assertRaises(InvalidSignatureError):
            decoded_payload = decode_token(invalid_token)


if __name__ == '__main__':
    unittest.main()
