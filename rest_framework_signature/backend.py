import hashlib
import hmac

from django.core.exceptions import ObjectDoesNotExist

from rest_framework_signature.settings import auth_settings


class MSSQLBackend(object):
    supports_inactive_user = False
    user_model = auth_settings.get_user_document()
    DUMMY_SALT = 'signature-login-dummy-salt'
    DUMMY_PASSWORD_HASH = '0' * 40

    def authenticate(self, request=None, username=None, password=None):
        user = self.get_user_by_username(username)
        # Missing users follow the same hash-and-compare path as real users.
        salt = user.salt if user and user.salt else self.DUMMY_SALT
        expected_hash = user.password if user else self.DUMMY_PASSWORD_HASH
        m = hashlib.sha1()
        m.update(password.encode('utf-8'))
        if type(salt) is bytes:
            m.update(salt)
        else:
            m.update(salt.encode('utf-8'))
        hashed_password = m.hexdigest()
        if user and hmac.compare_digest(expected_hash or '', hashed_password):
            return user
        return None

    def get_user_by_username(self, username):
        try:
            return self.user_model.objects.get(username=username)
        except ObjectDoesNotExist:
            return None

    def get_user(self, pk):
        try:
            return self.user_model.objects.get(pk=pk)
        except ObjectDoesNotExist:
            return None
