import django
import os
import uuid
import binascii
from unittest.mock import patch
from django.test import TestCase

os.environ['DJANGO_SETTINGS_MODULE'] = 'test_projects.test_proj.settings'
django.setup()

from rest_framework_signature import authentication
from rest_framework_signature.models.relational import ApiKey


class MockRequest:
    META = {}
    path = '/test'
    method = 'GET'
    api_key_id = None

    def get_full_path(self):
        return self.path


class AuthenticationTests(TestCase):

    mock_request = MockRequest()
    mock_auth_header = b'Token asdz3123'
    mock_token = 'blahToken'
    mock_user = {}

    @patch('rest_framework_signature.authentication.TokenAuthentication.authenticate_credentials')
    @patch('rest_framework_signature.authentication.TokenAuthentication.check_signature')
    @patch('rest_framework_signature.authentication.rest_framework.authentication')
    def test_authenticate_calls_check_signature(self, mock_rest_framework_authentication, mock_check_signature,
                                                mock_authenticate_credentials):
        # arrange
        api_key = ApiKey.objects.create(name=str(uuid.uuid4())[:30], access_key=binascii.hexlify(os.urandom(22)).decode(), secret_access_key=binascii.hexlify(os.urandom(22)).decode())
        mock_check_signature.return_value = api_key
        mock_authenticate_credentials.return_value = self.mock_user, self.mock_token
        mock_rest_framework_authentication.get_authorization_header.return_value = self.mock_auth_header
        reference = authentication.TokenAuthentication()

        # act
        reference.authenticate(self.mock_request)

        # assert
        mock_rest_framework_authentication.get_authorization_header.assert_called_with(self.mock_request)
        mock_check_signature.assert_called_with(self.mock_request)
        mock_authenticate_credentials.assert_called_with(self.mock_auth_header.split()[1])
