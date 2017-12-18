import bcrypt

from django.apps import AppConfig
from django.db import models
from django.dispatch import receiver
from django.utils import timezone


class TestCognitoAppConfig(AppConfig):
    name = 'test_projects.test_cognito_proj.test_cognito_app'

    def ready(self):
        @receiver(models.signals.pre_save, sender=self.get_model('User'))
        def user_pre_save(sender, **kwargs):
            instance = kwargs['instance']
            instance.updated = timezone.now()
            if instance.created is None:
                instance.created = timezone.now()
            if instance.salt is None:
                instance.salt = bcrypt.gensalt()