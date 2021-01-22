import binascii
import hashlib
import os
import uuid
from types import SimpleNamespace

from datetime import timedelta
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from rest_framework import response, status
from rest_framework_signature.authentication import TokenAuthentication
from rest_framework_signature.errors import ErrorMessages
from rest_framework_signature.helpers import RestFrameworkSignatureTestClass
from rest_framework_signature.settings import auth_settings
from unittest.mock import patch


class AuthenticationTestsWithApiKeyWithNoPermissions(RestFrameworkSignatureTestClass):
    def setUp(self):
        # create different token than default for no permissions
        access_key = str(uuid.uuid4())[:10]
        secret_access_key = str(uuid.uuid4())[:20]
        api_key = self.application_model(
            name=str(uuid.uuid4())[:15],
            access_key=access_key,
            secret_access_key=secret_access_key
        )
        api_key.save()
        self.setup_client(api_key=api_key)

        # give this api key some permissions
        self.endpoint_with_access = '/users'
        self.endpoint_with_access_with_request_permissions = '/apiEndpoints'

        self.create_endpoint_with_access(self.endpoint_with_access)
        self.create_endpoint_with_access_with_request_permissions(self.endpoint_with_access_with_request_permissions)

    def test_api_request_permission_with_permission_but_not_valid_key_returns_403(self):
        # arrange
        url = self.endpoint_with_access_with_request_permissions
        body = {
            'endpoint': str(uuid.uuid4())[:15]
        }
        headers = self.get_headers(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.data['detail'], ErrorMessages.API_KEY_NOT_AUTHORIZED_FOR_ENDPOINT.format(url))

    def test_api_request_permission_with_permission_but_not_valid_value_returns_403(self):
        # arrange
        url = self.endpoint_with_access_with_request_permissions
        body = {
            'endpoint': str(uuid.uuid4())[:15],
            self.api_request_permission_key: str(uuid.uuid4())[:15]
        }
        headers = self.get_headers(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.data['detail'], ErrorMessages.API_KEY_NOT_AUTHORIZED_FOR_ENDPOINT.format(url))

    def test_api_request_permission_with_permission_posts_ok(self):
        # arrange
        url = self.endpoint_with_access_with_request_permissions
        body = {
            'endpoint': str(uuid.uuid4())[:15],
            self.api_request_permission_key: self.api_request_permission_value
        }
        headers = self.get_headers(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 200)

    def test_get_endpoint_with_access(self):
        url = self.endpoint_with_access
        headers = self.get_headers(url)

        # act
        result = self.api_client.get(url, format='json', **headers)

        # assert
        self.assertEqual(result.status_code, status.HTTP_200_OK)

    def test_get_endpoint_without_access(self):
        url = '/apiKeys'
        headers = self.get_headers(url)

        # act
        result = self.api_client.get(url, format='json', **headers)

        # assert
        self.assertEquals(result.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEquals(result.data['detail'], ErrorMessages.API_KEY_NOT_AUTHORIZED_FOR_ENDPOINT.format(url))

    def test_request_fails_without_auth_header_due_to_bypass_user_auth_not_in_settings(self):
        # arrange
        url = self.endpoint_with_access
        headers = self.get_headers_without_auth(url)

        # act
        result = self.api_client.get(url, format='json', **headers)

        # assert
        self.assertEqual(result.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(result.data['detail'], TokenAuthentication.ErrorMessages.NO_AUTH_HEADER_PRESENT)


class AuthenticationTestsWithBypassAuthAPIKey(RestFrameworkSignatureTestClass):
    def setUp(self):
        # create different token than default for no permissions
        access_key = str(uuid.uuid4())[:10]
        secret_access_key = str(uuid.uuid4())[:20]
        api_key = self.application_model(
            name=str(uuid.uuid4())[:15],
            access_key=access_key,
            secret_access_key=secret_access_key,
            bypass_user_auth=True
        )
        api_key.save()
        self.setup_client(api_key=api_key)

        # give this api key some permissions
        self.endpoint_with_access = '/users'
        self.endpoint_with_access_with_request_permissions = '/apiEndpoints'

        self.create_endpoint_with_access(self.endpoint_with_access)
        self.create_endpoint_with_access_with_request_permissions(self.endpoint_with_access_with_request_permissions)

    def test_request_works_without_auth_header_due_to_bypass_user_auth_settings(self):
        url = self.endpoint_with_access
        headers = self.get_headers_without_auth(url)

        # act
        result = self.api_client.get(url, format='json', **headers)

        # assert
        self.assertEqual(result.status_code, status.HTTP_200_OK)


class AuthenticationTestsWithBypassUserAuthInSettings(RestFrameworkSignatureTestClass):
    def setUp(self):
        # create different token than default for no permissions
        access_key = str(uuid.uuid4())[:10]
        secret_access_key = str(uuid.uuid4())[:20]
        api_key = self.application_model(
            name='bypass_user_auth_key',
            access_key=access_key,
            secret_access_key=secret_access_key
        )
        api_key.save()
        self.setup_client(api_key=api_key)

        # give this api key some permissions
        self.endpoint_with_access = '/users'
        self.endpoint_with_access_with_request_permissions = '/apiEndpoints'

        self.create_endpoint_with_access(self.endpoint_with_access)
        self.create_endpoint_with_access_with_request_permissions(self.endpoint_with_access_with_request_permissions)

    def test_request_works_without_auth_header_due_to_bypass_user_auth_settings(self):
            url = self.endpoint_with_access
            headers = self.get_headers_without_auth(url)

            # act
            result = self.api_client.get(url, format='json', **headers)

            # assert
            self.assertEqual(result.status_code, status.HTTP_200_OK)


class AuthenticationTestsWithFullAccessAPIKey(RestFrameworkSignatureTestClass):
    def setUp(self):
        # create different token than default for no permissions
        access_key = str(uuid.uuid4())[:10]
        secret_access_key = str(uuid.uuid4())[:20]
        api_key = self.application_model(
            name=str(uuid.uuid4())[:15],
            access_key=access_key,
            secret_access_key=secret_access_key,
            full_access=True
        )
        api_key.save()
        self.setup_client(api_key=api_key)

    def test_get_endpoint_without_access_but_with_full_access_api_key_in_db_returns_200(self):
        url = '/apiKeys'
        headers = self.get_headers(url)

        # act
        result = self.api_client.get(url, format='json', **headers)

        # assert
        self.assertEquals(result.status_code, status.HTTP_200_OK)


class AuthenticationTests(RestFrameworkSignatureTestClass):
    user_model = auth_settings.get_user_document()

    @staticmethod
    def failed_token_lookup(*_args, **kwargs):
        raise ObjectDoesNotExist

    @staticmethod
    def successful_token_lookup(user, token, *_args, **_kwargs):
        return SimpleNamespace(user=user, token=token)

    @staticmethod
    def generate_token_class(user=None, token=None, lookup=None):
        class TokenClass:
            class objects:
                pass

        token_class = TokenClass()
        token_class.objects.get = lambda *_args, **_kwargs: lookup(user, token)

        return token_class

    @staticmethod
    def generate_failed_lookup_class():
        return AuthenticationTests.generate_token_class(lookup=AuthenticationTests.failed_token_lookup)

    @staticmethod
    def generate_successful_lookup_class(user, token=''):
        return AuthenticationTests.generate_token_class(
            user=user, token=token,
            lookup=AuthenticationTests.successful_token_lookup,
        )

    @patch('rest_framework_signature.settings.auth_settings.get_sso_token_classes')
    def test_sso_login_with_multiple_token_classes_succeeds_after_fails(self, mock_sso_classes):
        # arrange
        user = self.user_model.objects.get(username=self.user.username)

        mock_sso_classes.return_value = [
            self.generate_failed_lookup_class(),
            self.generate_successful_lookup_class(user=user),
        ]

        url = '/auth/sso_login'
        body = {}
        headers = self.get_headers(url)

        # act
        result = self.api_client.post(url, body, **headers)

        # assert
        self.assertEquals(result.status_code, status.HTTP_200_OK)

    @patch('rest_framework_signature.settings.auth_settings.get_sso_token_classes')
    def test_sso_login_with_multiple_token_classes_fails(self, mock_sso_classes):
        # arrange
        mock_sso_classes.return_value = [
            self.generate_failed_lookup_class()
            for _ in range(3)
        ]

        url = '/auth/sso_login'
        body = { }
        headers = self.get_headers(url)

        # act
        result = self.api_client.post(url, body, **headers)

        # assert
        self.assertEqual(result.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('rest_framework_signature.settings.auth_settings.get_sso_token_classes')
    def test_sso_login_fails_with_no_(self, mock_sso_classes):
        # arrange
        mock_sso_classes.return_value = None

        url = '/auth/sso_login'
        body = { }
        headers = self.get_headers(url)

        # act
        result = self.api_client.post(url, body, **headers)

        # assert
        self.assertEqual(result.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('test_projects.test_proj.test_app.views.UserHandler.get')
    def test_add_api_key_id_to_request(self, mock_get):
        mock_get.return_value = response.Response({}, status=status.HTTP_200_OK)
        url = '/users'
        headers = self.get_headers(url)
        result = self.api_client.get(url, **headers)

        # asserts
        self.assertEqual(result.status_code, 200)
        self.assertTrue(mock_get.called)
        first_call = mock_get.call_args_list[0]
        request_arg = first_call[0][0]
        self.assertEqual(request_arg.api_key_id, self.device_token.id)

    def test_get_endpoint_without_access_but_with_full_access_api_key_in_settings_returns_200(self):
        url = '/apiKeys'
        headers = self.get_headers(url)

        # act
        result = self.api_client.get(url, format='json', **headers)

        # assert
        self.assertEquals(result.status_code, status.HTTP_200_OK)

    def test_incorrect_api_key_returns_invalid_api_key_error(self):
        url = '/users'
        result = self.api_client.get(url)
        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.data['detail'],
                         '{0} {1}'.format(ErrorMessages.PERMISSION_DENIED, ErrorMessages.MISSING_API_KEY))

    def test_invalid_nonce_returns_invalid_nonce_error(self):
        url = '/users'
        headers = self.get_headers(url, {})
        headers[auth_settings.NONCE_HEADER] = 'garbagio'
        result = self.api_client.get(url, **headers)
        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.data['detail'],
                         '{0} {1}'.format(ErrorMessages.PERMISSION_DENIED, ErrorMessages.INVALID_NONCE))

    def test_no_nonce_returns_missing_nonce_error(self):
        url = '/users'
        body = {
            'garbage': 'collector'
        }
        headers = self.get_headers(url)
        del headers[auth_settings.NONCE_HEADER]
        result = self.api_client.get(url, body, **headers)
        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.data['detail'],
                         '{0} {1}'.format(ErrorMessages.PERMISSION_DENIED, ErrorMessages.MISSING_NONCE))

    def test_multi_filters_url_escaping(self):
        # arrange
        url = '/users?filters=client_id=1|is_active=True&include=report'
        headers = self.get_headers(url)

        # act
        result = self.api_client.get(url, format='json', **headers)

        # assert
        self.assertEqual(result.status_code, status.HTTP_200_OK)

    def test_post_check_reset_password_link(self):
        self.user.password_reset_token = binascii.hexlify(os.urandom(22)).decode()
        self.user.password_reset_token_created = timezone.now()
        self.user.password_reset_token_expires = timezone.now() + timedelta(hours=1)
        self.user.save()
        url = '/auth/check_password_reset_link'
        body = {'reset_token': self.user.password_reset_token}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 200)

    def test_post_check_reset_password_link_expired_token(self):
        self.user.password_reset_token = binascii.hexlify(os.urandom(22)).decode()
        self.user.password_reset_token_created = timezone.now()
        self.user.password_reset_token_expires = timezone.now() - timedelta(hours=3)
        self.user.save()
        url = '/auth/check_password_reset_link'
        body = {'reset_token': self.user.password_reset_token}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.data['error_message'], ErrorMessages.INVALID_RESET_PASSWORD_TOKEN)

    def test_post_check_reset_password_link_invalid_reset_token(self):
        url = '/auth/check_password_reset_link'
        body = {'reset_token': '12315sdf'}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.data['error_message'], ErrorMessages.INVALID_RESET_PASSWORD_TOKEN)

    def test_post_check_reset_password_link_no_reset_token(self):
        url = '/auth/check_password_reset_link'
        body = {}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.data['error_message'], ErrorMessages.INVALID_RESET_PASSWORD_TOKEN)

    def test_post_login(self):
        url = '/auth/login'
        body = {
            'username': self.user.username,
            'password': self.sha1_password
        }
        result = self.api_client.post(url, body, format='json')
        self.assertEqual(result.status_code, 200)

    def test_post_login_with_correct_password_clears_failed_login_attempts(self):
        url = '/auth/login'
        body = {
            'username': self.user.username,
            'password': 'wrong'
        }
        self.api_client.post(url, body, format='json')
        url = '/auth/login'
        body = {
            'username': self.user.username,
            'password': self.sha1_password
        }
        result = self.api_client.post(url, body, format='json')
        self.assertEqual(result.status_code, 200)
        user = self.user_model.objects.get(username=self.user.username)
        self.assertEqual(user.failed_login_attempts, 0)

    def test_post_login_with_correct_password_clears_last_failed_login(self):
        url = '/auth/login'
        body = {
            'username': self.user.username,
            'password': 'wrong'
        }
        self.api_client.post(url, body, format='json')
        url = '/auth/login'
        body = {
            'username': self.user.username,
            'password': self.sha1_password
        }
        result = self.api_client.post(url, body, format='json')
        self.assertEqual(result.status_code, 200)
        user = self.user_model.objects.get(username=self.user.username)
        self.assertIsNone(user.last_failed_login)

    def test_post_login_with_incorrect_password_20_times_locks_account(self):
        url = '/auth/login'
        body = {
            'username': self.user.username,
            'password': 'wrong'
        }
        for x in range(20):
            result = self.api_client.post(url, body, format='json')
        self.assertEqual(result.status_code, 400)
        data = result.data
        self.assertEqual(data['error_message'], ErrorMessages.TOO_MANY_INCORRECT_LOGIN_ATTEMPTS)

    def test_post_login_with_incorrect_password_updates_failed_login_attempts(self):
        url = '/auth/login'
        body = {
            'username': self.user.username,
            'password': 'wrong'
        }
        result = self.api_client.post(url, body, format='json')
        self.assertEqual(result.status_code, 400)
        data = result.data
        self.assertEqual(data['error_message'], ErrorMessages.INVALID_CREDENTIALS)
        user = self.user_model.objects.get(username=self.user.username)
        self.assertEqual(user.failed_login_attempts, 1)

    def test_post_login_with_incorrect_password_updates_last_failed_login(self):
        url = '/auth/login'
        body = {
            'username': self.user.username,
            'password': 'wrong'
        }
        result = self.api_client.post(url, body, format='json')
        self.assertEqual(result.status_code, 400)
        data = result.data
        self.assertEqual(data['error_message'], ErrorMessages.INVALID_CREDENTIALS)
        user = self.user_model.objects.get(username=self.user.username)
        self.assertIsNotNone(user.last_failed_login)

    def test_post_login_with_incorrect_username(self):
        url = '/auth/login'
        body = {
            'username': 'garble',
            'password': self.sha1_password
        }
        result = self.api_client.post(url, body, format='json')
        self.assertEqual(result.status_code, 400)
        data = result.data
        self.assertEqual(data['error_message'], ErrorMessages.INVALID_CREDENTIALS)

    def test_post_login_with_no_username(self):
        url = '/auth/login'
        body = {}
        result = self.api_client.post(url, body, format='json')
        self.assertEqual(result.status_code, 400)
        data = result.data
        self.assertEqual(data['error_message'], ErrorMessages.MISSING_USERNAME_OR_PASSWORD)

    def test_post_logout(self):
        url = '/auth/logout'
        headers = self.get_headers(url)
        result = self.api_client.post(url, format='json', **headers)
        self.assertEqual(result.status_code, 204)

    def test_post_reset_password_invalid_username(self):
        url = '/auth/reset_password'
        body = {'username': 'doesnotexist@test.com'}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.data['error_message'], ErrorMessages.INVALID_USERNAME)

    def test_post_reset_password_no_username(self):
        url = '/auth/reset_password'
        body = {}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.data['error_message'], ErrorMessages.MISSING_USERNAME)

    def test_post_reset_password_sets_reset_password_token(self):
        url = '/auth/reset_password'
        body = {'username': self.user.username}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 200)
        user = self.user_model.objects.get(username=self.user.username)
        self.assertIsNotNone(user.password_reset_token)
        self.assertIsNotNone(user.password_reset_token_created)

    def test_post_submit_new_password_no_reset_token(self):
        url = '/auth/submit_new_password'
        body = {}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.data['error_message'], ErrorMessages.INVALID_RESET_PASSWORD_TOKEN)

    def test_post_submit_new_password_invalid_reset_token(self):
        url = '/auth/submit_new_password'
        body = {'reset_token': '12315sdf'}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.data['error_message'], ErrorMessages.INVALID_RESET_PASSWORD_TOKEN)

    def test_post_submit_new_password_link_expired_token(self):
        self.user.password_reset_token = binascii.hexlify(os.urandom(22)).decode()
        self.user.password_reset_token_created = timezone.now()
        self.user.password_reset_token_expires = timezone.now() - timedelta(hours=3)
        self.user.save()
        url = '/auth/submit_new_password'
        body = {'reset_token': self.user.password_reset_token}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.data['error_message'], ErrorMessages.INVALID_RESET_PASSWORD_TOKEN)

    def test_post_submit_new_password_link_no_password(self):
        self.user.password_reset_token = binascii.hexlify(os.urandom(22)).decode()
        self.user.password_reset_token_created = timezone.now()
        self.user.password_reset_token_expires = timezone.now() + timedelta(hours=1)
        self.user.save()
        url = '/auth/submit_new_password'
        body = {'reset_token': self.user.password_reset_token}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.data['error_message'], ErrorMessages.NO_PASSWORD)

    def test_post_submit_new_password_link(self):
        self.user.password_reset_token = binascii.hexlify(os.urandom(22)).decode()
        self.user.password_reset_token_created = timezone.now()
        self.user.password_reset_token_expires = timezone.now() + timedelta(hours=1)
        self.user.save()
        url = '/auth/submit_new_password'
        new_password = 'test1234'
        body = {'reset_token': self.user.password_reset_token, 'password': new_password}
        headers = self.get_headers_without_auth(url, body)
        result = self.api_client.post(url, body, format='json', **headers)
        self.assertEqual(result.status_code, 200)
        user = self.user_model.objects.get(username=self.user.username)
        m = hashlib.sha1()
        m.update(new_password.encode('utf-8'))
        if type(self.user.salt) is bytes:
            m.update(self.user.salt)
        else:
            m.update(self.user.salt.encode('utf-8'))
        expected_password = m.hexdigest()
        self.assertEqual(expected_password, user.password)
