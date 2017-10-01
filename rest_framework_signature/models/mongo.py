import binascii
import datetime
import os
import re

from mongoengine import Document, StringField, ReferenceField, DateTimeField, DictField, IntField
from mongoengine import signals
from mongoengine.errors import ValidationError
from mongoengine.django.auth import User as MongoEngineUser


class ApiEndpoint(Document):
    endpoint = StringField()


class ApiPermission(Document):
    api_key = ReferenceField('Application', required=True)
    api_endpoint = ReferenceField('ApiEndpoint', required=True)
    methods = StringField()


class Application(Document):
    """ An application consumer of this API. This will be our mobile app and
    each website that we have
    """
    name = StringField(primary_key=True)
    access_key = StringField(required=True)
    secret_access_key = StringField(required=True)

    meta = {
        'indexes': [
            'access_key'
        ]
    }

    @classmethod
    def pre_save(cls, sender, document, **kwargs):
        if not document.access_key:
            document.access_key = binascii.hexlify(os.urandom(22)).decode()
            document.secret_access_key = binascii.hexlify(os.urandom(22)).decode()


signals.pre_save.connect(Application.pre_save, sender=Application)


class AuthToken(Document):
    key = StringField()
    auth_type = StringField()
    user = ReferenceField('User', required=True)
    updated = DateTimeField()
    created = DateTimeField()

    def __unicode__(self):
        return self.key

    @classmethod
    def pre_save(cls, sender, document, **kwargs):
        if not document.key:
            document.key = binascii.hexlify(os.urandom(22)).decode()
        if hasattr(document, 'updated'):
            document.updated = datetime.datetime.utcnow()

        if hasattr(document, 'created') and not document.created:
            document.created = datetime.datetime.utcnow()


signals.pre_save.connect(AuthToken.pre_save, sender=AuthToken)


class User(MongoEngineUser):
    username = StringField(max_length=50, required=True,
                           verbose_name='email')
    salt = StringField()
    email = StringField(required=False)
    auth_tokens = DictField()
    password_reset_token = StringField()
    password_reset_token_created = DateTimeField()
    password_reset_token_expires = DateTimeField(null=True)
    password_reset_ip = StringField()
    failed_login_attempts = IntField(default=0)
    last_failed_login = DateTimeField()

    meta = {
        'allow_inheritance': True,
        'indexes': [
            {'fields': ['username'], 'unique': True, 'sparse': True},
        ],
    }

    @staticmethod
    def validate_email(email):
        email_regex = re.compile('^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$', re.IGNORECASE)
        if not email_regex.match(email):
            return False
        return True

    @classmethod
    def pre_save(cls, sender, document):
        if not cls.validate_email(document.username):
            raise ValidationError('Did not provide valid e-mail address')

signals.pre_save.connect(User.pre_save, sender=User)
