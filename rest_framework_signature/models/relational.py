import uuid

from django.core.validators import MinLengthValidator
from django.db import models
from django.utils import timezone


def generate_key():
    return str(uuid.uuid4())[:20]


class ApiEndpoint(models.Model):
    id = models.AutoField(primary_key=True)
    endpoint = models.CharField(max_length=150, null=False, blank=False)


class ApiKey(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=128)
    access_key = models.CharField(max_length=128, default=generate_key)
    secret_access_key = models.CharField(max_length=128, default=generate_key)
    bypass_user_auth = models.BooleanField(default=False)
    full_access = models.BooleanField(default=False)
    updated = models.DateTimeField(null=False, default=timezone.now)
    created = models.DateTimeField(null=False, default=timezone.now)


class ApiPermission(models.Model):
    id = models.AutoField(primary_key=True)
    api_key = models.ForeignKey('ApiKey', null=False, on_delete=models.CASCADE)
    api_endpoint = models.ForeignKey('ApiEndpoint', null=False, on_delete=models.CASCADE)
    methods = models.CharField(max_length=32, null=True, blank=True)


class ApiRequestPermission(models.Model):
    id = models.AutoField(primary_key=True)
    api_key = models.ForeignKey('ApiKey', null=False, on_delete=models.CASCADE)
    api_endpoint = models.ForeignKey('ApiEndpoint', null=False, on_delete=models.CASCADE)
    request_key = models.CharField(max_length=32, null=False, blank=False)
    request_value = models.CharField(max_length=32, null=False, blank=False)


class AuthToken(models.Model):
    id = models.AutoField(primary_key=True)
    key = models.CharField(max_length=80, null=False, default=generate_key)
    auth_type = models.CharField(max_length=150, null=True, blank=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    updated = models.DateTimeField(null=False, default=timezone.now)
    created = models.DateTimeField(null=False, default=timezone.now)


class User(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=80, null=True, blank=True)
    password = models.CharField(max_length=128, null=True, blank=True)
    first_name = models.CharField(max_length=100, null=False)
    last_name = models.CharField(max_length=100, null=False)
    is_active = models.BooleanField(null=False, default=True)
    created = models.DateTimeField(null=False, default=timezone.now)
    created_by = models.ForeignKey('User', null=True, blank=True, related_name='users_created', on_delete=models.CASCADE)
    updated = models.DateTimeField(null=False, default=timezone.now)
    updated_by = models.ForeignKey('User', null=True, blank=True, related_name='users_updated', on_delete=models.CASCADE)
    salt = models.CharField(max_length=50, null=True, blank=True)
    password_reset_token = models.CharField(max_length=50, null=True, blank=True)
    password_reset_token_created = models.DateTimeField(null=True, blank=True)
    password_reset_token_expires = models.DateTimeField(null=True, blank=True)
    password_reset_ip = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(null=True, blank=True, default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)

    @property
    def email(self):
        return self.username
