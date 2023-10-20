# Import your models from your application
from Himalia.models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token, User
import unittest

# Create a mock database session for testing
from unittest.mock import MagicMock
db = MagicMock()


# Create a mock database session for testing
db = MagicMock()


class TestOAuth2Models(unittest.TestCase):

    def setUp(self):
        self.client_data = {
            'username': 'client_username',
            'client_id': 'client_id',
            'client_uri': 'https://example.com/client_uri',
            'secret_id': 'secret_id',
            'redirect_uri': 'https://example.com/redirect_uri',
        }

        self.auth_code_data = {
            'user_id': 1,
            'authcode': 'authorization_code',
            'scope': 'read write',
            'expires_at': 1634697600  # Some expiration timestamp
        }

        self.token_data = {
            'user_id': 1,
            'jwt_token': 'jwt_token_data'
        }
        self.user_data = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'username': 'johndoe',
            'password': 'secretpassword'
        }

    def test_oauth2_client_creation(self):
        client = OAuth2Client(**self.client_data)

        # Mock the behavior of db.session
        db.session.add.return_value = None
        db.session.commit.return_value = None

        # Perform the creation
        db.session.add(client)
        db.session.commit()

        # Assert that the appropriate methods were called on db.session
        db.session.add.assert_called_with(client)
        db.session.commit.assert_called()

    def test_oauth2_authorization_code_creation(self):
        auth_code = OAuth2AuthorizationCode(**self.auth_code_data)

        # Mock the behavior of db.session
        db.session.add.return_value = None
        db.session.commit.return_value = None

        # Perform the creation
        db.session.add(auth_code)
        db.session.commit()

        # Assert that the appropriate methods were called on db.session
        db.session.add.assert_called_with(auth_code)
        db.session.commit.assert_called_once()

    def test_oauth2_token_creation(self):
        token = OAuth2Token(**self.token_data)

        # Mock the behavior of db.session
        db.session.add.return_value = None
        db.session.commit.return_value = None

        # Perform the creation
        db.session.add(token)
        db.session.commit()

        # Assert that the appropriate methods were called on db.session
        db.session.add.assert_called_with(token)
        db.session.commit.assert_called()

    def test_user_creation(self):
        user = User(**self.user_data)
        self.assertEqual(user.name, self.user_data['name'])
        self.assertEqual(user.email, self.user_data['email'])
        self.assertEqual(user.username, self.user_data['username'])
        self.assertTrue(user.check_password(self.user_data['password']))

    def test_get_user_id(self):
        user = User(**self.user_data)
        # The user has not been added to the database yet
        self.assertIsNone(user.get_user_id())

    def test_get_email(self):
        user = User(**self.user_data)
        self.assertEqual(user.get_email(), self.user_data['email'])


if __name__ == '__main__':
    unittest.main()
