import django
import os
import unittest
import uuid

os.environ['DJANGO_SETTINGS_MODULE'] = 'test_projects.test_cognito_proj.settings'
django.setup()

from rest_framework_signature.helpers import RestFrameworkSignatureTestClass
from rest_framework import status


class CognitoAuthenticationTests(RestFrameworkSignatureTestClass):
    def test_register(self):
        url = '/auth/register'
        body = {
            'cognitoSubId': str(uuid.uuid4())[:30] + str(uuid.uuid4())[:6]
        }
        headers = self.get_headers_without_auth(url, body=body)

        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, status.HTTP_201_CREATED)

    @unittest.mock.patch('rest_framework_signature.jwt_validator.get_client_id_from_access_token')
    @unittest.mock.patch('rest_framework_signature.jwt_validator.get_claims')
    def test_get_api_keys(self, mock_get_claims, mock_client_id):
        client_id = str(uuid.uuid4())[:15]
        mock_client_id.return_value = client_id
        mock_get_claims.return_value = {
            'sub': self.user.cognito_sub_id,
        }
        url = '/apiKeys'
        headers = self.get_headers(url)

        result = self.api_client.get(url, format='json', **headers)
        self.assertEqual(result.status_code, status.HTTP_200_OK)
