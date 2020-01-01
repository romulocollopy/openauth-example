"""
    https://python-social-auth.readthedocs.io/en/latest/backends/scopes.html
"""
from social_core.utils import handle_http_errors
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthMissingParameter


class ScopesOAuth2(BaseOAuth2):
    """Scopes OAuth2 authentication backend"""
    name = 'scopes-to'

    REDIRECT_STATE = False

    AUTHORIZATION_URL = 'http://localhost:8003/o/authorize/'
    ACCESS_TOKEN_URL = 'http://localhost:8003/o/token/'
    REVOKE_TOKEN_URL = 'http://localhost:8003/o/revoke_token/'
    ACCESS_TOKEN_METHOD = 'POST'

    # The order of the default scope is important
    DEFAULT_SCOPE = []
    EXTRA_DATA = [
        ('refresh_token', 'refresh_token', True),
        ('expires_in', 'expires'),
        ('token_type', 'token_type', True)
    ]

    def get_user_id(self, details, response):
        return response.get('id') or details.get('username')

    def get_user_details(self, response):
        fields = ['username', 'email', 'name', 'first_name', 'last_name']
        return {field: response.get(field, '') for field in fields}

    def user_data(self, access_token, *args, **kwargs):
        return self.get_json(
            'http://localhost:8003/api/profile/',
            headers={
                'Authorization': 'Bearer %s' % access_token,
            },
        )

    def revoke_token_params(self, token, uid):
        return {'token': token}

    def revoke_token_headers(self, token, uid):
        return {'Content-type': 'application/json'}
