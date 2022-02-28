import re

import rest_framework.authentication
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ObjectDoesNotExist
from django.utils.encoding import uri_to_iri
from jose.exceptions import JWSError, JWTError
from mongoengine.errors import DoesNotExist
from rest_framework import exceptions

from rest_framework_signature.settings import auth_settings
from rest_framework_signature.helpers import get_nonce, get_timestamp_milliseconds, get_hours_in_milliseconds
from rest_framework_signature.jwt_validator import get_claims, get_client_id_from_access_token
from rest_framework_signature.errors import ErrorMessages


class TokenAuthentication(rest_framework.authentication.BaseAuthentication):
    """
    Simple token based authentication.
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ".  For example:
        Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a
    A custom token model may be used, but must have the following properties.
    * key -- The string identifying the token
    * user -- The user to which the token belongs
    """

    class ErrorMessages:
        NO_AUTH_HEADER_PRESENT = 'No Auth Header Present'

    cognito_enabled = auth_settings.COGNITO_ENABLED
    if not cognito_enabled:
        auth_token_model = auth_settings.get_auth_token_document()
    bypass_auth_urls = auth_settings.BYPASS_URLS
    unsecured_urls = auth_settings.UNSECURED_URLS

    def authenticate(self, request):

        # if it is an unsecured url then bypass auth
        request_path = request.path
        if (request.method, request_path) in self.unsecured_urls:
            return

        # first check if they are sending a super key to bypass all auth
        super_key_header = auth_settings.SUPER_KEY_HEADER
        super_key = request.META.get(super_key_header, None) if super_key_header else None
        if super_key and auth_settings.SUPER_KEY_AUTH and super_key == auth_settings.SUPER_KEY_AUTH:
            return AnonymousUser, None

        # first thing check the signature of the request
        api_key = self.check_signature(request)

        # special case for posting new users
        if (request.method, request_path) in self.bypass_auth_urls:
            return

        # if they've disabled user auth simply return an anonymous user
        if auth_settings.DISABLE_USER_AUTH:
            return AnonymousUser, None

        # if specific API keys do not need user auth then bypass it
        bypass_user_auth_setting = auth_settings.BYPASS_USER_AUTH_API_KEY_NAMES and api_key.name in auth_settings.BYPASS_USER_AUTH_API_KEY_NAMES
        bypass_user_auth_api_key = hasattr(api_key, 'bypass_user_auth') and getattr(api_key, 'bypass_user_auth', False)
        if bypass_user_auth_setting or bypass_user_auth_api_key:
            return AnonymousUser, None

        # regular authentication
        auth_header = rest_framework.authentication.get_authorization_header(request)
        if not self.cognito_enabled:
            auth = auth_header.split()

            if not auth or auth[0].lower() != b'token':
                raise exceptions.AuthenticationFailed('No Auth Header Present')

            if len(auth) == 1:
                msg = 'Invalid token header. No credentials provided.'
                raise exceptions.AuthenticationFailed(msg)
            elif len(auth) > 2:
                msg = 'Invalid token header. Token string should not contain spaces.'
                raise exceptions.AuthenticationFailed(msg)

            return self.authenticate_credentials(auth[1])
        else:
            if not auth_header:
                raise exceptions.AuthenticationFailed(self.ErrorMessages.NO_AUTH_HEADER_PRESENT)
            try:
                cognito_client_id = get_client_id_from_access_token(auth_header)
            except (JWSError, JWTError) as ex:
                raise exceptions.AuthenticationFailed('Error decoding token: {0}'.format(ex.args[0]))
            try:
                claims = get_claims(auth_header, cognito_client_id)
            except (JWSError, JWTError) as ex:
                raise exceptions.AuthenticationFailed('Error decoding token: {0}'.format(ex.args[0]))
            return self.authenticate_cognito(claims)

    @staticmethod
    def authenticate_cognito(claims):
        sub = claims.get('sub', None)
        user_model = auth_settings.get_user_document()
        try:
            user = user_model.objects.get(cognito_sub_id=sub)
        except ObjectDoesNotExist:
            raise exceptions.AuthenticationFailed('No user found with cognito sub: {0}'.format(sub))
        else:
            return user, None

    def authenticate_credentials(self, key):
        try:
            token = self.auth_token_model.objects.select_related('user').get(key=key.decode('UTF-8'))
        except (DoesNotExist, ObjectDoesNotExist):
            raise exceptions.AuthenticationFailed('Invalid token')

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or deleted')

        # check if the token has expired
        expire_time = get_hours_in_milliseconds(auth_settings.AUTH_TOKEN_EXPIRATION)
        token_created = get_timestamp_milliseconds(dt=token.updated)
        current_time = get_timestamp_milliseconds()
        if token_created + expire_time < current_time:
            raise exceptions.AuthenticationFailed('Token expired - reauthenticate')
        return token.user, token

    def authenticate_header(self, request):
        return 'Token'

    def check_signature(self, request):
        application_model = auth_settings.get_application_document()
        # collect required headers
        timestamp = request.META.get(auth_settings.TIMESTAMP_HEADER, None)
        nonce = request.META.get(auth_settings.NONCE_HEADER, None)
        api_key = request.META.get(auth_settings.API_KEY_HEADER, None)

        # grab url request is for
        url = uri_to_iri(request.get_full_path())

        # Un-escape the following characters, for the url nonce calculation specifically
        url = url.replace('%7C', '|')
        url = url.replace('%20', ' ')
        url = url.replace('%27', '\'')

        # if no api key was passed in raise error
        if not api_key:
            raise exceptions.PermissionDenied(ErrorMessages.PERMISSION_DENIED + ' ' + ErrorMessages.MISSING_API_KEY)

        # get corresponding DeviceToken for request
        try:
            token = application_model.objects.get(access_key=api_key)
        except (DoesNotExist, ObjectDoesNotExist):
            raise exceptions.PermissionDenied(ErrorMessages.PERMISSION_DENIED + ' ' + ErrorMessages.INVALID_API_KEY)

        # set api key id on request
        # todo: move this out of check signature!~~~~~~~~!@@!
        request.api_key_id = token.id

        # ensure that the api key has access to this url
        api_key_has_access = self.validate_api_key(token, url, request.method, request)
        if not api_key_has_access:
            raise exceptions.PermissionDenied(ErrorMessages.API_KEY_NOT_AUTHORIZED_FOR_ENDPOINT.format(url))

        # to prevent replay attacks if timestamp isn't within last 3 seconds deny request
        current_timestamp = get_timestamp_milliseconds() - auth_settings.REPLAY_ATTACK_TIME
        if not timestamp or int(timestamp) < current_timestamp:
            raise exceptions.PermissionDenied(ErrorMessages.PERMISSION_DENIED + ' ' + ErrorMessages.REPLAY_ERROR)

        if auth_settings.MULTIPART_POST_URLS and url in auth_settings.MULTIPART_POST_URLS:
            return token

        # if no nonce was passed in raise error
        if not nonce:
            raise exceptions.PermissionDenied(ErrorMessages.PERMISSION_DENIED + ' ' + ErrorMessages.MISSING_NONCE)

        # if it is a get we are finished
        if request.method in ('GET', 'DELETE'):
            valid_nonce = get_nonce(timestamp, url, token.secret_access_key)
        # post requires us to alphabetize the request data by key
        elif request.method in ('POST', 'PATCH', 'PUT'):
            valid_nonce = get_nonce(timestamp, url, token.secret_access_key, body=request.data)
        else:
            valid_nonce = None

        if valid_nonce != nonce:
            raise exceptions.PermissionDenied(ErrorMessages.PERMISSION_DENIED + ' ' + ErrorMessages.INVALID_NONCE)

        return token

    @staticmethod
    def validate_api_key(api_key, url, method, request):
        full_access_settings = auth_settings.FULL_ACCESS_API_KEY_NAMES and \
                               api_key.name in auth_settings.FULL_ACCESS_API_KEY_NAMES
        full_access_api_key = hasattr(api_key, 'full_access') and getattr(api_key, 'full_access', False)
        if full_access_settings or full_access_api_key:
            return True

        # check if we have permissions to this method
        method_permission = False

        # get the api permission model
        api_permission_model = auth_settings.get_api_permission_document()

        # grab all method permissions
        for api_permission in api_permission_model.objects.filter(api_key=api_key):
            # check each endpoint to see if url matches the regex
            reg_ex = re.compile(api_permission.api_endpoint.endpoint)
            if reg_ex.match(url):
                # we matched the regex now just see if we have access to that method
                available_methods = api_permission.methods.split(',')
                if method in available_methods:
                    method_permission = True
                    break

        # if I don't have access to this endpoint don't do any further checks and return False
        if not method_permission:
            return False

        # get the api request permission model
        api_request_permission_model = auth_settings.get_api_request_permission_document()

        # grab all request permissions
        request_permission = True
        for api_request_permission in api_request_permission_model.objects.filter(api_key=api_key):
            # check each endpoint to see if url matches the regex
            reg_ex = re.compile(api_request_permission.api_endpoint.endpoint)
            if reg_ex.match(url):
                # we matched the regex now just see if we have access with these parameters
                request_permission = False
                if (api_request_permission.request_key in request.data.keys()) and (api_request_permission.request_value == request.data.get(api_request_permission.request_key, None)):
                    return True

        return request_permission
