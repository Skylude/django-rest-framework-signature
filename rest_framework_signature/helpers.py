import hashlib
import hmac
import io
import json
import time
import unittest
import uuid
from collections import OrderedDict
import warnings

import bcrypt
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.utils import timezone
from django.test import TestCase
from rest_framework.test import APIClient

from rest_framework_signature.settings import auth_settings


def get_hours_in_milliseconds(hours):
    return hours * 60 * 60 * 1000


def get_nonce(timestamp, url, secret_access_key, body=None):
    m = hmac.new(secret_access_key.encode(), digestmod=hashlib.sha1)
    m.update(str(timestamp).encode('utf-8'))
    m.update(url.encode('utf-8'))
    if body:
        sorted_body = sort_body(body)
        sorted_json = json.dumps(sorted_body, ensure_ascii=False).replace(' ', '')
        m.update(sorted_json.encode('utf-8'))
    return m.hexdigest()


def get_timestamp_milliseconds(dt=None):
    if not dt:
        dt = timezone.now()
    # grab time since epoch milliseconds
    return int(time.mktime(dt.timetuple())*1000 + dt.microsecond/1000)


def sort_body(data):
    """
    Where possible, sorts all dictionary and dictionary-like items by key. Reliably sorts
    root-level dictionaries, nested dictionaries, and stringified dictionaries. OrderedDict,
    list, and set types will not be sorted, but the objects they contain are subject to sorting.

    Some edge cases may produce unexpected sorting, including but not limited to:
        - Strings with JSON, list, or set formatted contents will be converted to dict format, with objects
            cast to their inferred types as per json.loads() best judgement
        - OrderedDicts keys won't be sorted, but OrderedDict[key] values will have a sort attempted
        - If contained in a dict, lists and sets will recursively sort each item. Items are not sorted
            within the list, but are sorted within themselves
                Example: sort_body({"a": [{"c": 1, "b": 2}]}) == {"a": [{"b": 2. "c": 1}]}

    :param data: The payload to be sorted before nonce calculation
    :return: Sorted data
    """
    if isinstance(data, dict):
        sorted_result = OrderedDict()
        # Only sort by keys in dictionaries. Keys should be strings, and must all be the same object type.
        #   sorted() fails silently when comparing different types, such as a string and an integer.
        for key, value in sorted(data.items()):
            # everything will be in unicode unless we've converted it and went to the next level of depth
            if isinstance(value, str):
                try:
                    # If we parse the JSON successfully, give the work to a further nested sort_body function
                    parsed_value = json.loads(value)
                    if isinstance(parsed_value, dict) or isinstance(parsed_value, list) or isinstance(parsed_value, set):
                        sorted_result[key] = sort_body(parsed_value)
                    else:  # we only want to use the parsed value if result is dict
                        sorted_result[key] = value
                except ValueError:
                    sorted_result[key] = value
            elif isinstance(value, dict) or isinstance(value, OrderedDict):
                sorted_result[key] = sort_body(value)
            elif isinstance(value, list) or isinstance(value, set):
                # Sorting arrays breaks compatibility, cannot be implemented in drfsig 1.x
                sorted_result[key] = [sort_body(list_item) for list_item in value]
            elif isinstance(value, io.TextIOWrapper) or isinstance(value, InMemoryUploadedFile):
                # There's no sorting to be done with a file.
                continue
            else:
                sorted_result[key] = value
        return sorted_result
    if isinstance(data, list) or isinstance(data, set):
        # Just in case the list contains dictionaries that need sorted
        return [sort_body(list_item) for list_item in data]
    # Anything that isn't a list or dict gets ignored
    return data


def check_valid_reset_token(reset_token, user):
    # check if the reset_token has expired
    expire_time = get_timestamp_milliseconds(user.password_reset_token_expires)
    current_time = get_timestamp_milliseconds()
    is_expired = expire_time < current_time

    if user.password_reset_token != reset_token or is_expired:
        return False

    return True


def generate_email_address():
    return '{0}@{1}.com'.format(str(uuid.uuid4())[:10], str(uuid.uuid4())[:5])


class RestFrameworkSignatureTestClass(TestCase):

    cognito_enabled = auth_settings.COGNITO_ENABLED
    user_model = auth_settings.get_user_document()
    application_model = auth_settings.get_application_document()
    if not cognito_enabled:
        auth_token_model = auth_settings.get_auth_token_document()

    def get_headers(self, url, body=None):
        if not hasattr(self, '_api_client'):
            self.setup_client()

        headers = self.get_headers_without_auth(url, body)
        if not self.cognito_enabled:
            headers['HTTP_AUTHORIZATION'] = 'Token {0}'.format(self.token.key)
        else:
            headers['HTTP_AUTHORIZATION'] = self.token
        return headers

    def get_headers_without_auth(self, url, body=None):
        if not hasattr(self, '_api_client'):
            self.setup_client()

        timestamp = str(get_timestamp_milliseconds())
        nonce = get_nonce(str(timestamp), url, self.device_token.secret_access_key, body=body)

        headers = {
            auth_settings.TIMESTAMP_HEADER: str(timestamp),
            auth_settings.NONCE_HEADER: nonce,
            auth_settings.API_KEY_HEADER: self.device_token.access_key
        }
        return headers

    def setUp(self):
        warnings.filterwarnings(action="ignore", message="unclosed", category=ResourceWarning)
        warnings.filterwarnings(action="ignore", message="DateTimeField", category=RuntimeWarning)

    @property
    def api_client(self):
        if not hasattr(self, '_api_client'):
            self.setup_client()
        return self._api_client
    
    @property
    def user(self):
        if not hasattr(self, '_api_client'):
            self.setup_client()
        return self._user

    @property
    def device_token(self):
        if not hasattr(self, '_api_client'):
            self.setup_client()
        return self._device_token

    @property
    def sha1_password(self):
        if not hasattr(self, '_api_client'):
            self.setup_client()
        return self._sha1_password

    def setup_client(self):
        # create client to access api endpoints
        self._api_client = APIClient()

        if not self.cognito_enabled:
            # create a user to use to authenticate against
            username = generate_email_address()
            salt = bcrypt.gensalt()
            m = hashlib.sha1()
            m.update('pass1234'.encode('utf-8'))
            sha1_password = m.hexdigest()
            m = hashlib.sha1()
            m.update(sha1_password.encode('utf-8'))
            m.update(salt)
            password = m.hexdigest()
            test_user = self.user_model(
                username=username,
                password=password,
                salt=salt
            )
            test_user.save()
            # create an authentication token
            token, created = self.auth_token_model.objects.get_or_create(user=test_user)
            self._sha1_password = sha1_password
            self.token = token
        else:
            # this is just made up so you will need to mock your cognito user otherwise all will fail
            cognito_sub_id = str(uuid.uuid4())[:30] + str(uuid.uuid4())[:6]
            test_user = self.user_model(
                cognito_sub_id=cognito_sub_id
            )
            test_user.save()
            self.token = str(uuid.uuid4())[:15]

        # create a signature DeviceToken to hash our requests
        access_key = str(uuid.uuid4())[:10]
        secret_access_key = str(uuid.uuid4())[:20]
        device_token = self.application_model(
            name='test-app',
            access_key=access_key,
            secret_access_key=secret_access_key
        )
        device_token.save()
        self._user = test_user
        self._device_token = device_token

    def tearDown(self):
        warnings.resetwarnings()

    class MockRequestsResponse:
        def __init__(self, status_code, text, mock_json_cb=None):
            self.status_code = status_code
            self.text = text
            self.mock_json_cb = mock_json_cb

        def json(self):
            return self.mock_json_cb
