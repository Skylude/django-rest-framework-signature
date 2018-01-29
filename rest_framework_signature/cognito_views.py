import binascii
from datetime import timedelta
import hashlib
import os

import bcrypt
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.utils import timezone
from rest_framework_signature.settings import auth_settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView


class RegisterUser(APIView):
    def post(self, request):
        user_model = auth_settings.get_user_document()
        cognito_sub_id = request.data.get('cognitoSubId', None)

        if not cognito_sub_id:
            res = {
                'errorMessage': user_model.ErrorMessages.NO_SUB_ID_PROVIDED
            }
            return Response(data=res, status=status.HTTP_400_BAD_REQUEST, content_type='application/json')

        user = user_model(cognito_sub_id=cognito_sub_id)

        try:
            user.save()
        except ValidationError as ex:
            res = {
                'errorMessage': ex.args[0]
            }
            return Response(data=res, status=status.HTTP_400_BAD_REQUEST, content_type='application/json')

        res = {
            'id': user.id
        }
        return Response(data=res, status=status.HTTP_201_CREATED, content_type='application/json')


register_user = RegisterUser.as_view()
