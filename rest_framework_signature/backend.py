import hashlib

from django.core.exceptions import ObjectDoesNotExist

from rest_framework_signature.settings import auth_settings


class MSSQLBackend(object):
    supports_inactive_user = False
    user_model = auth_settings.get_user_document()

    def authenticate(self, request=None, username=None, password=None):
        user = self.get_user_by_username(username)
        if not user:
            return None
        m = hashlib.sha1()
        m.update(password.encode('utf-8'))
        if type(user.salt) is bytes:
            m.update(user.salt)
        else:
            m.update(user.salt.encode('utf-8'))
        hashed_password = m.hexdigest()
        if user.password == hashed_password:
            return user
        else:
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
