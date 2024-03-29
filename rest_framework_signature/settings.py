from django.conf import settings
from django.test.signals import setting_changed
from django.utils.module_loading import import_module

from rest_framework_signature.exceptions import InvalidAuthSettings


USER_SETTINGS = getattr(settings, 'REST_FRAMEWORK_SIGNATURE', None)

# SSO Tokens HAVE to have a user attribute and a token attribute on them
DEFAULTS = {
    'AUTH_TOKEN_EXPIRATION': 168,  # hours
    'RESET_PASSWORD_TOKEN_EXPIRATION': 1,  # hours
    'FAILED_LOGIN_FREEZE_TIME': 20, # minutes
    'FAILED_LOGIN_RETRY_ATTEMPTS': 20,
    'USER_DOCUMENT': None,
    'AUTH_TOKEN_DOCUMENT': None,
    'APPLICATION_DOCUMENT': None,
    'API_PERMISSION_MODEL': None,
    'API_REQUEST_PERMISSION_MODEL': None,
    'API_ENDPOINT_MODEL': None,
    'DB_SETTINGS': None,
    'SUPER_KEY_AUTH': None,
    'SUPER_KEY_HEADER': None,
    'TIMESTAMP_HEADER': 'HTTP_X_DRFSIG_TIMESTAMP',
    'NONCE_HEADER': 'HTTP_X_DRFSIG_NONCE',
    'API_KEY_HEADER': 'HTTP_X_DRFSIG_API_KEY',
    'DATABASE_ENGINE': None,
    'REPLAY_ATTACK_TIME': 60000,  # milliseconds
    'DISABLE_USER_AUTH': False,
    'BYPASS_URLS': [
        ('POST', '/users'),
        ('POST', '/auth/reset_password'),
        ('POST', '/auth/check_password_reset_link'),
        ('POST', '/auth/submit_new_password')
    ],
    'UNSECURED_URLS': [
        ('GET', '/auth/ping')
    ],
    'SSO_TOKEN_CLASSES': None,
    'FULL_ACCESS_API_KEY_NAMES': None,
    'BYPASS_USER_AUTH_API_KEY_NAMES': None,
    'MULTIPART_POST_URLS': None
}


class AuthSettings(object):
    class ErrorMessages:
        NOT_PROVIDED = '{0} setting not properly configured'

    required_settings = [
        'APPLICATION_DOCUMENT',
        'API_ENDPOINT_MODEL',
        'API_PERMISSION_MODEL',
        'API_REQUEST_PERMISSION_MODEL',
        'DATABASE_ENGINE',
        'USER_DOCUMENT'
    ]

    def __init__(self, user_settings=None, defaults=None):
        self.user_settings = user_settings or {}
        self.defaults = defaults or DEFAULTS

        # validate authentication settings
        self.validate_settings()

    def __getattr__(self, attr):
        if attr not in self.defaults.keys():
            raise AttributeError("Invalid AUTH settings: {0}".format(attr))

        # settings that need to be appended to not overwritten
        if attr == 'BYPASS_URLS' or attr == 'UNSECURED_URLS':
            try:
                val = self.user_settings[attr] + self.defaults[attr]
            except KeyError:
                val = self.defaults[attr]
        else:
            try:
                val = self.user_settings[attr]
            except KeyError:
                val = self.defaults[attr]

        setattr(self, attr, val)
        return val

    def get_user_document(self):
        try:
            name = self.user_settings['USER_DOCUMENT']
        except KeyError:
            name = self.defaults['USER_DOCUMENT']
        dot = name.rindex('.')
        module = import_module(name[:dot])
        return getattr(module, name[dot + 1:])

    def get_auth_token_document(self):
        try:
            name = self.user_settings['AUTH_TOKEN_DOCUMENT']
        except KeyError:
            name = self.defaults['AUTH_TOKEN_DOCUMENT']
        dot = name.rindex('.')
        module = import_module(name[:dot])
        return getattr(module, name[dot + 1:])

    def get_api_endpoint_document(self):
        try:
            name = self.user_settings['API_ENDPOINT_MODEL']
        except KeyError:
            name = self.defaults['API_ENDPOINT_MODEL']
        dot = name.rindex('.')
        module = import_module(name[:dot])
        return getattr(module, name[dot + 1:])

    def get_api_permission_document(self):
        try:
            name = self.user_settings['API_PERMISSION_MODEL']
        except KeyError:
            name = self.defaults['API_PERMISSION_MODEL']
        dot = name.rindex('.')
        module = import_module(name[:dot])
        return getattr(module, name[dot + 1:])

    def get_api_request_permission_document(self):
        try:
            name = self.user_settings['API_REQUEST_PERMISSION_MODEL']
        except KeyError:
            name = self.defaults['API_REQUEST_PERMISSION_MODEL']
        dot = name.rindex('.')
        module = import_module(name[:dot])
        return getattr(module, name[dot + 1:])

    def get_application_document(self):
        try:
            name = self.user_settings['APPLICATION_DOCUMENT']
        except KeyError:
            name = self.defaults['APPLICATION_DOCUMENT']
        dot = name.rindex('.')
        module = import_module(name[:dot])
        return getattr(module, name[dot + 1:])

    def get_sso_token_classes(self):
        try:
            token_class_names = self.user_settings['SSO_TOKEN_CLASSES']
        except KeyError:
            return None
        else:
            token_classes = []
            for token_class in token_class_names:
                dot = token_class.rindex('.')
                module = import_module(token_class[:dot])
                token_classes.append(getattr(module, token_class[dot + 1:]))
            return token_classes

    def validate_settings(self):
        for required_setting in self.required_settings:
            if required_setting not in self.user_settings.keys():
                raise InvalidAuthSettings(self.ErrorMessages.NOT_PROVIDED.format(required_setting))

        # ensure we have all the models we need
        if 'AUTH_TOKEN_DOCUMENT' not in self.user_settings.keys():
            raise InvalidAuthSettings(self.ErrorMessages.NOT_PROVIDED.format('AUTH_TOKEN_DOCUMENT'))

        # todo: validate user model fields


auth_settings = AuthSettings(USER_SETTINGS, DEFAULTS)


def reload_auth_settings(*args, **kwargs):
    global auth_settings
    setting, value = kwargs['setting'], kwargs['value']
    if setting == 'REST_FRAMEWORK_SIGNATURE':
        auth_settings = AuthSettings(value, DEFAULTS)


setting_changed.connect(reload_auth_settings)
