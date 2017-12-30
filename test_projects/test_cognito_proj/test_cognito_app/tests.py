import binascii
import bcrypt
from datetime import timedelta
import django
import hashlib
import os
import unittest
import uuid

os.environ['DJANGO_SETTINGS_MODULE'] = 'test_projects.test_cognito_proj.settings'
django.setup()

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from rest_framework_signature.errors import ErrorMessages
from rest_framework_signature.helpers import RestFrameworkSignatureTestClass, generate_email_address
from rest_framework_signature.settings import auth_settings
from rest_framework.test import APIClient
from rest_framework import response, status


class CognitoAuthenticationTests(RestFrameworkSignatureTestClass):
    def test_login(self):
        self.assertEqual(1,1)