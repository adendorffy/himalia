import unittest
from unittest.mock import patch
from Himalia.app import create_app, db
from Himalia.models import User, OAuth2Token, OAuth2AuthorizationCode
from Himalia.oauth2 import (validate_user_token,
                            validate_user_authcode,
                            store_user_authcode,
                            create_token,
                            delete_token,
                            issue_jwt,
                            get_user_from_code,
                            store_user_token,)
from unittest.mock import MagicMock
import jwt
import time


class TestOAuth2Functions(unittest.TestCase):

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

    def test_validate_user_token(self):
        # Add test data to the database
        db.session.add(self.user)
        db.session.add(self.token)
        db.session.commit()

        # Perform queries against the testing database
        queried_user = User.query.filter_by(name='John Doe').first()
        queried_token = OAuth2Token.query.filter_by(
            jwt_token='valid_token').first()
        val = validate_user_token(self.token.jwt_token)

        self.assertIsNotNone(queried_user)
        self.assertIsNotNone(queried_token)
        self.assertEqual(val, True)

    def test_incorrect_validate_user_token(self):
        # Add test data to the database
        db.session.add(self.user)
        db.session.add(self.token)
        db.session.commit()

        # Perform queries against the testing database
        queried_user = User.query.filter_by(name='John Doe').first()
        queried_token = OAuth2Token.query.filter_by(
            jwt_token='valid_token').first()
        val = validate_user_token('invalid_token')

        self.assertIsNotNone(queried_user)
        self.assertIsNotNone(queried_token)
        self.assertEqual(val, False)

    def test_validate_user_authcode(self):
        # Mock the behavior of OAuth2AuthorizationCode.query.filter_by
        auth_code = MagicMock(expires_at=int(time.time()) + 300)
        self.OAuth2AuthorizationCode.query.filter_by.return_value.first.return_value = auth_code

        # Call the function under test
        result = validate_user_authcode('valid_code')
        print(result)
        # Assert that the function behaves as expected
        self.assertFalse(result)

    def test_store_user_authcode(self):
        # Mock the behavior of db.session
        self.db.session = MagicMock()
        self.db.session.add = MagicMock()
        self.db.session.commit = MagicMock()
        # Call the function under test
        store_user_authcode('user', 'code', 'scope_string')
        # Assert that the appropriate methods were called
        self.assertEqual(self.db.session.add.call_count, 0)

    @patch('Himalia.oauth2.validate_user_authcode', return_value=True)
    # Replace with appropriate user ID
    @patch('Himalia.oauth2.get_user_from_code', return_value=1)
    @patch('Himalia.oauth2.issue_jwt', return_value='mocked_token')
    @patch('Himalia.oauth2.store_user_token', return_value='mocked_token')
    def test_create_token_success(self, store_user_token_mock, issue_jwt_mock, get_user_from_code_mock, validate_user_authcode_mock):

        # Arrange
        code = 'valid_code'

        # Create a mock code_record with a scope attribute
        code_record_mock = MagicMock(spec=OAuth2AuthorizationCode)
        code_record_mock.scope = 'mocked_scope'

        # Mock the behavior of filter_by
        filter_by_mock = MagicMock()
        filter_by_mock.first.return_value = code_record_mock

        # Mock the behavior of OAuth2AuthorizationCode.query
        query_mock = MagicMock()
        query_mock.filter_by = filter_by_mock

        # Replace the query behavior
        with patch('Himalia.oauth2.OAuth2AuthorizationCode.query', query_mock):
            # Act
            token = create_token(code)

            # Assert
            # Expect 'mocked_token' as the return value
            self.assertEqual(token, 'mocked_token')

    @patch('Himalia.oauth2.validate_user_authcode', return_value=False)
    @patch('Himalia.oauth2.get_user_from_code')
    def test_create_token_validation_failure(self, get_user_from_code_mock, validate_user_authcode_mock):
        # Arrange
        code = 'invalid_code'

        # Act
        token = create_token(code)

        # Assert
        self.assertIsNone(token)
        self.assertEqual(validate_user_authcode_mock.call_count, 1)
        self.assertEqual(get_user_from_code_mock.call_count, 0)

    def test_store_user_token(self):
        # Mock the behavior of db.session
        self.db.session = MagicMock()
        self.db.session.add = MagicMock()
        self.db.session.commit = MagicMock()
        # Call the function under test
        store_user_token('code', 'valid_token')
        # Assert that the appropriate methods were called
        self.assertEqual(self.db.session.add.call_count, 0)

    def test_get_user_from_code(self):
        db.session.add(self.user)
        db.session.add(self.authcode)
        db.session.commit()

        # Perform queries against the testing database
        queried_user = User.query.filter_by(name='John Doe').first()
        queried_code = OAuth2AuthorizationCode.query.filter_by(
            authcode='valid_code').first()
        code = get_user_from_code(self.authcode.authcode)
        self.assertIsNotNone(queried_user)
        self.assertNotEqual(self.authcode.authcode, code)
        self.assertIsNotNone(queried_code)

    def test_correct_scope_issue_jwt(self):
        # test that scopes are correctly set (1 scope)
        # make fake jwt
        test_scope = "email"
        iss_at = int(time.time())
        time_exp = int(time.time()) + 86400
        claims = {
            'issued_at': iss_at,
            'exp': time_exp,  # Expiration time
            'scope': test_scope,  # Scope
            'token_type': "Bearer",
            "iss": "Himalia",
            "id": 1
        }
        test_jwt = jwt.encode(claims, 'secret_key', algorithm='HS256')
        ret_token = issue_jwt(test_scope, 1)
        # decode both and compare scopes

        test_jwt = jwt.decode(test_jwt, 'secret_key', algorithms=['HS256'])
        ret_token = jwt.decode(ret_token, 'secret_key', algorithms=['HS256'])

        # Test 1 : 1 scope
        self.assertEqual(test_jwt['scope'], ret_token['scope'][0])

    def test_delete_token(self):
        # Add test data to the database
        db.session.add(self.user)
        db.session.add(self.token)
        db.session.commit()

        # Perform queries against the testing database
        queried_user = User.query.filter_by(name='John Doe').first()
        queried_token = OAuth2Token.query.filter_by(
            jwt_token='valid_token').first()

        delete_token(self.token.jwt_token)
        self.assertIsNotNone(queried_user)
        self.assertIsNotNone(queried_token)
        self.assertEqual(self.db.session.delete.call_count, 0)

    def test_wrong_scope_issue_jwt(self):
        # Test 2: wrong scope 1
        test_scope = "email"
        iss_at = int(time.time())
        time_exp = int(time.time()) + 86400
        claims = {
            'issued_at': iss_at,
            'exp': time_exp,  # Expiration time
            'scope': test_scope,  # Scope
            'token_type': "Bearer",
            "iss": "Himalia",
            "id": 1
        }
        test_jwt = jwt.encode(claims, 'secret_key', algorithm='HS256')
        ret_token = issue_jwt('username', 1)
        # decode both and compare scopes

        test_jwt = jwt.decode(test_jwt, 'secret_key', algorithms=['HS256'])
        ret_token = jwt.decode(ret_token, 'secret_key', algorithms=['HS256'])

        assert test_jwt.get('scope') != ret_token.get('scope')[0]

    def test_more_than_1_scope_issue_jwt(self):
        # Test 2: wrong scope 1
        test_scope = ["email", "username"]
        iss_at = int(time.time())
        time_exp = int(time.time()) + 86400
        claims = {
            'issued_at': iss_at,
            'exp': time_exp,  # Expiration time
            'scope': test_scope,  # Scope
            'token_type': "Bearer",
            "iss": "Himalia",
            "id": 1
        }
        test_jwt = jwt.encode(claims, 'secret_key', algorithm='HS256')
        ret_token = issue_jwt("email,username", 1)
        # decode both and compare scopes

        test_jwt = jwt.decode(test_jwt, 'secret_key', algorithms=['HS256'])
        ret_token = jwt.decode(ret_token, 'secret_key', algorithms=['HS256'])

        assert test_jwt.get('scope') == ret_token.get('scope')

    def test_more_than_1_invalid_scope_issue_jwt(self):
        # Test 2: wrong scope 1
        test_scope = ["email", "username"]
        iss_at = int(time.time())
        time_exp = int(time.time()) + 86400
        claims = {
            'issued_at': iss_at,
            'exp': time_exp,  # Expiration time
            'scope': test_scope,  # Scope
            'token_type': "Bearer",
            "iss": "Himalia",
            "id": 1
        }
        test_jwt = jwt.encode(claims, 'secret_key', algorithm='HS256')
        ret_token = issue_jwt("email,username,user_id", 1)
        # decode both and compare scopes

        test_jwt = jwt.decode(test_jwt, 'secret_key', algorithms=['HS256'])
        ret_token = jwt.decode(ret_token, 'secret_key', algorithms=['HS256'])
        matched = 0
        mismatch = 0
        for el in ret_token.get('scope'):
            if (el == test_jwt.get('scope')[0]):
                matched += 1
            else:
                mismatch += 1
            if (el == test_jwt.get('scope')[1]):
                matched += 1
            else:
                mismatch += 1

        self.assertEqual(matched, 2)
        self.assertEqual(mismatch, 4)


if __name__ == '__main__':
    unittest.main()
