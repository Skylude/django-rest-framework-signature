from django.db import models

from rest_framework_signature.models.relational import ApiEndpoint, ApiKey, ApiPermission, ApiRequestPermission, \
    AuthToken, User as SignatureUser


class User(SignatureUser):
    new_field = models.CharField(max_length=12, null=True, blank=True)
