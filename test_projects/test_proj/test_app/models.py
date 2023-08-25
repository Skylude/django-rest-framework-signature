from django.db import models
from django.utils import timezone

from rest_framework_signature.models.relational import (
    ApiEndpoint,
    ApiKey,
    ApiPermission,
    ApiRequestPermission,
    AuthToken,
    User as SignatureUser,
)


def get_token_expiration():
    return timezone.now() + timezone.timedelta(seconds=15)


class User(SignatureUser):
    new_field = models.CharField(max_length=12, null=True, blank=True)


class SSOToken(models.Model):
    token = models.CharField(max_length=80, null=False, blank=False, db_column='token')
    user = models.ForeignKey(
        "User",
        null=False,
        related_name="sso_tokens",
        db_column="user_id",
        on_delete=models.CASCADE,
    )
    expires = models.DateTimeField(
        null=False,
        db_column="expires",
        default=get_token_expiration,
    )

class SSOTokenTwo(models.Model):
    token = models.CharField(max_length=80, null=False, blank=False, db_column='token')
    user = models.ForeignKey(
        "User",
        null=False,
        related_name="sso_tokens_two",
        db_column="user_id",
        on_delete=models.CASCADE,
    )
