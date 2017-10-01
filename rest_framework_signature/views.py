import binascii
from datetime import timedelta
import hashlib
import os

import bcrypt
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from mongoengine.errors import DoesNotExist
from rest_framework_signature.helpers import check_valid_reset_token
from rest_framework_signature.serializers import AuthTokenSerializer, SSOTokenSerializer
from rest_framework_signature.settings import auth_settings
from rest_framework import status, authentication
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_signature.errors import ErrorMessages


class DeleteAuthToken(APIView):
    def post(self, request):
        auth_token_model = auth_settings.get_auth_token_document()
        auth = authentication.get_authorization_header(request).split()

        try:
            token = auth_token_model.objects.get(user=request.user, key=auth[1].decode('utf-8'))
        except (DoesNotExist, ObjectDoesNotExist):
            return Response(status=status.HTTP_400_BAD_REQUEST)
        token.delete()

        if auth_settings.DATABASE_ENGINE == 'mongo':
            # have to cascade_save to ensure parent documents are deleted -- due to inheritance in mongoengine
            token.cascade_save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class GetAuthToken(ObtainAuthToken):
    auth_token_model = auth_settings.get_auth_token_document()
    model = auth_token_model
    user_model = auth_settings.get_user_document()
    # set authentication classes to empty as this needs to be open for them to obtain their auth token
    authentication_classes = ()
    serializer_class = AuthTokenSerializer

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token, created = self.model.objects.get_or_create(user=user, auth_type='password')
            if not created:
                token.updated = timezone.now()
                token.save()

            user.failed_login_attempts = 0
            user.save()
            response = {'token': token.key, 'userId': serializer.validated_data['user'].id}
            return Response(response, content_type='application/json', status=status.HTTP_200_OK)

        # increase incorrect login attempts
        username = request.data.get('username', None)
        if username:
            try:
                user = self.user_model.objects.get(username=username)
                if user.failed_login_attempts is None:
                    user.failed_login_attempts = 0
                user.failed_login_attempts += 1
                user.last_failed_login = timezone.now()
                user.save()
                if user.failed_login_attempts >= auth_settings.FAILED_LOGIN_RETRY_ATTEMPTS:
                    response = {'error_message': ErrorMessages.TOO_MANY_INCORRECT_LOGIN_ATTEMPTS}
                    return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)
            except (DoesNotExist, ObjectDoesNotExist):
                pass
        response = {'error_message': serializer.friendly_error_message}
        return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)


class GetAuthTokenSSO(ObtainAuthToken):
    auth_token_model = auth_settings.get_auth_token_document()
    model = auth_token_model
    user_model = auth_settings.get_user_document()
    # set authentication classes to empty as this needs to be open for them to obtain their auth token
    authentication_classes = ()
    serializer_class = SSOTokenSerializer

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token, created = self.model.objects.get_or_create(user=user, auth_type='sso')
            if not created:
                token.updated = timezone.now()
                token.save()

            user.failed_login_attempts = 0
            user.save()
            response = {'token': token.key, 'userId': serializer.validated_data['user'].id}
            return Response(response, content_type='application/json', status=status.HTTP_200_OK)

        # todo: block them if too many sso attempts?
        response = {'error_message': ErrorMessages.INVALID_CREDENTIALS}
        return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)


class ResetPassword(APIView):
    user_model = auth_settings.get_user_document()

    def post(self, request):

        username = request.data.get('username', None)
        if not username:
            response = {'error_message': ErrorMessages.MISSING_USERNAME}
            return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)

        try:
            user = self.user_model.objects.get(username=username)
        except (DoesNotExist, ObjectDoesNotExist):
            response = {'error_message': ErrorMessages.INVALID_USERNAME}
            return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)

        # create verification token
        user.password_reset_token = binascii.hexlify(os.urandom(22)).decode()
        user.password_reset_token_created = timezone.now()
        user.password_reset_token_expires = timezone.now() + timedelta(hours=auth_settings.RESET_PASSWORD_TOKEN_EXPIRATION)
        user.save()

        # send email
        # send email with password_reset_token link
        response = {'reset_password_token': user.password_reset_token, 'user_email': user.email}
        return Response(response, status=status.HTTP_200_OK)


class CheckPasswordResetLink(APIView):
    user_model = auth_settings.get_user_document()

    def post(self, request):
        reset_token = request.data.get('reset_token', None)

        if not reset_token:
            response = {'error_message': ErrorMessages.INVALID_RESET_PASSWORD_TOKEN}
            return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)

        try:
            user = self.user_model.objects.get(password_reset_token=reset_token)
        except (DoesNotExist, ObjectDoesNotExist):
            response = {'error_message': ErrorMessages.INVALID_RESET_PASSWORD_TOKEN}
            return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)

        valid_reset_token = check_valid_reset_token(reset_token, user)
        if not valid_reset_token:
            response = {'error_message': ErrorMessages.INVALID_RESET_PASSWORD_TOKEN}
            return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)

        response = {'success': True}
        return Response(response, status=status.HTTP_200_OK)


class SubmitNewPassword(APIView):
    user_model = auth_settings.get_user_document()

    def post(self, request):

        reset_token = request.data.get('reset_token', None)

        if not reset_token:
            response = {'error_message': ErrorMessages.INVALID_RESET_PASSWORD_TOKEN}
            return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)

        try:
            user = self.user_model.objects.get(password_reset_token=reset_token)
        except (DoesNotExist, ObjectDoesNotExist):
            response = {'error_message': ErrorMessages.INVALID_RESET_PASSWORD_TOKEN}
            return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)

        valid_reset_token = check_valid_reset_token(reset_token, user)
        if not valid_reset_token:
            response = {'error_message': ErrorMessages.INVALID_RESET_PASSWORD_TOKEN}
            return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)

        password = request.data.get('password', None)
        if not password:
            response = {'error_message': ErrorMessages.NO_PASSWORD}
            return Response(response, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)

        m = hashlib.sha1()
        if user.salt is None:
            user.salt = bcrypt.gensalt()
        m.update(password.encode('utf-8'))
        m.update(user.salt.encode('utf-8'))
        user.password = m.hexdigest()
        user.password_reset_ip = request.META.get('REMOTE_ADDR', None)
        user.password_reset_token = None
        user.save()

        response = {'success': True}
        return Response(response, status=status.HTTP_200_OK)


class Ping(APIView):
    user_model = auth_settings.get_user_document()
    def get(self, request):
        response = {'success': True}
        return Response(response, status=status.HTTP_200_OK)


check_password_reset_link = CheckPasswordResetLink.as_view()
delete_auth_token = DeleteAuthToken.as_view()
obtain_auth_token = GetAuthToken.as_view()
obtain_auth_token_sso = GetAuthTokenSSO.as_view()
reset_password = ResetPassword.as_view()
submit_new_password = SubmitNewPassword.as_view()
ping = Ping.as_view()

