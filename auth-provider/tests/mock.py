from unittest.mock import Mock

class MockUser:
    def __init__(self, id, name, email, username, password):
        self.id = id
        self.name = name
        self.email = email
        self.username = username
        self.password = password

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        # Simulate password verification by comparing the provided password
        # with the stored password hash
        return self.password == password

    def get_email(self):
        return self.email

    def delete(self):
        pass

class MockOAuth2AuthorizationCode:
    def __init__(self, id, user_id, authcode, scope, expires_at):
        self.id = id
        self.user_id = user_id
        self.authcode = authcode
        self.scope = scope
        self.expires_at = expires_at

    def delete(self):
        pass

class MockOAuth2Token:
    def __init__(self, id, user_id, jwt_token):
        self.id = id
        self.user_id = user_id
        self.jwt_token = jwt_token
    def get_token(self,token):
        if token==self.jwt_token:
            return True
        else:
            return False