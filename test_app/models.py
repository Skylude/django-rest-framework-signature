import bcrypt

from django.db import models
from django.dispatch import receiver
from django.utils import timezone

from rest_framework_signature.models.relational import ApiEndpoint, ApiKey, ApiPermission, AuthToken, User as RDAuthUser


class User(RDAuthUser):
    new_field = models.CharField(max_length=12, null=True, blank=True)

@receiver(models.signals.pre_save, sender=User)
def user_pre_save(sender, **kwargs):
    instance = kwargs['instance']
    instance.updated = timezone.now()
    if instance.created is None:
        instance.created = timezone.now()
    if instance.salt is None:
        instance.salt = bcrypt.gensalt()
