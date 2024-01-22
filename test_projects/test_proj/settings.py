"""
Django settings for rest_framework_signature test project.

Generated by 'django-admin startproject' using Django 1.9.7.

For more information on this file, see
https://docs.djangoproject.com/en/1.9/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.9/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.9/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'l(st8u59z6dbs4f$h#)+b=n!x8_om@1jcl&=*(b_%-(_$$=oo8'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework.authtoken',
    'rest_framework',
    'rest_framework_signature.apps.RestFrameworkSignatureAppConfig',
    'test_projects.test_proj.test_app.apps.TestAppConfig',
]

MIDDLEWARE_CLASSES = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'test_projects.test_proj.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'test_proj.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.9/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'drfsig',
        'USER': 'test',
        'PASSWORD': 'test',
        'HOST': 'localhost',
        'PORT': '5432'
    }
}


# auth settings
AUTHENTICATION_BACKENDS = (
    'rest_framework_signature.backend.MSSQLBackend',
)


# Password validation
# https://docs.djangoproject.com/en/1.9/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/1.9/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.9/howto/static-files/
STATIC_URL = '/static/'


# rest framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_signature.authentication.TokenAuthentication',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    )
}


# authentication settings
REST_FRAMEWORK_SIGNATURE = {
    'SUPER_KEY_AUTH': 'super-key-test',
    'DATABASE_ENGINE': 'mssql',
    'USER_DOCUMENT': 'test_projects.test_proj.test_app.models.User',
    'APPLICATION_DOCUMENT': 'test_projects.test_proj.test_app.models.ApiKey',
    'AUTH_TOKEN_DOCUMENT': 'test_projects.test_proj.test_app.models.AuthToken',
    'API_PERMISSION_MODEL': 'test_projects.test_proj.test_app.models.ApiPermission',
    'API_REQUEST_PERMISSION_MODEL': 'test_projects.test_proj.test_app.models.ApiRequestPermission',
    'API_ENDPOINT_MODEL': 'test_projects.test_proj.test_app.models.ApiEndpoint',
    'BYPASS_URLS': [],
    'SSO_TOKEN_CLASSES': [
        'test_projects.test_proj.test_app.models.SSOToken',
        'test_projects.test_proj.test_app.models.SSOTokenTwo',
    ],
    'FULL_ACCESS_API_KEY_NAMES': ['test-app'],
    'BYPASS_USER_AUTH_API_KEY_NAMES': ['bypass_user_auth_key'],
    'MULTIPART_POST_URLS': [],
    'UNSECURED_URLS': []
}
