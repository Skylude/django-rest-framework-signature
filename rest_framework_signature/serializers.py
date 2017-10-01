from datetime import timedelta

from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from rest_framework_signature.settings import auth_settings
from rest_framework import exceptions, serializers

from rest_framework_signature.errors import ErrorMessages


class AuthTokenSerializer(serializers.Serializer):
    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    username = serializers.CharField(allow_blank=True, required=False)
    password = serializers.CharField(allow_blank=True, required=False)
    friendly_error_message = None

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

            if user:
                if not user.is_active:
                    self.friendly_error_message = ErrorMessages.ACCOUNT_DISABLED
                    raise exceptions.ValidationError(self.friendly_error_message)

                if user.last_failed_login:
                    login_freeze = user.last_failed_login + timedelta(minutes=auth_settings.FAILED_LOGIN_FREEZE_TIME)
                    if user.failed_login_attempts >= 5 and timezone.now() < login_freeze:
                        self.friendly_error_message = ErrorMessages.TOO_MANY_INCORRECT_LOGIN_ATTEMPTS
                        raise exceptions.ValidationError(self.friendly_error_message)

                user.failed_login_attempts = 0
                user.last_failed_login = None
                user.save()
            else:
                self.friendly_error_message = ErrorMessages.INVALID_CREDENTIALS
                raise exceptions.ValidationError(self.friendly_error_message)
        else:
            self.friendly_error_message = ErrorMessages.MISSING_USERNAME_OR_PASSWORD
            raise exceptions.ValidationError(self.friendly_error_message)

        attrs['user'] = user
        return attrs


class SSOTokenSerializer(serializers.Serializer):
    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    sso_token = serializers.CharField(allow_blank=True, required=False)
    friendly_error_message = None

    def validate(self, attrs):
        sso_token = attrs.get('sso_token')
        sso_token_classes = auth_settings.get_sso_token_classes()
        if not sso_token_classes:
            self.friendly_error_message = ErrorMessages.NO_SSO_TOKEN_CLASSES_DEFINED
            raise exceptions.ValidationError(self.friendly_error_message)

        for sso_token_class in sso_token_classes:
            try:
                sso_token_obj = sso_token_class.objects.get(token=sso_token)
            except ObjectDoesNotExist:
                self.friendly_error_message = ErrorMessages.NO_SSO_TOKEN_FOUND
                raise exceptions.ValidationError(self.friendly_error_message)
            else:
                attrs['user'] = sso_token_obj.user
                return attrs
