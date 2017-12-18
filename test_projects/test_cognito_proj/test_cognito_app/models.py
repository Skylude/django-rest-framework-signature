from django.db import models

from rest_framework_signature.models.relational import ApiEndpoint, ApiKey, ApiPermission, AuthToken, User as SignatureUser


class User(SignatureUser):
    cognito_id = models.CharField(max_length=80, null=True, blank=True)
