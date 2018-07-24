import os
import uuid

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.9/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'l(st8u59z6dbs4f$h#)+b=n!x8_em@1jcl&=*(b_%-(_$$=oo8'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework.authtoken',
    'rest_framework',
    'rest_framework_signature.apps.RestFrameworkSignatureAppConfig',
    'test_projects.test_cognito_proj.test_cognito_app.apps.TestCognitoAppConfig',
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

ROOT_URLCONF = 'test_projects.test_cognito_proj.urls'

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


# Database
# https://docs.djangoproject.com/en/1.9/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'drfsig_cognito',
        'USER': 'test',
        'PASSWORD': 'test',
        'HOST': 'localhost',
        'PORT': ''
    }
}


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
    'COGNITO_ENABLED': True,
    'COGNITO_REGION': str(uuid.uuid4())[:10],
    'COGNITO_USER_POOL': str(uuid.uuid4())[:30],
    'DATABASE_ENGINE': 'mssql',
    'USER_DOCUMENT': 'test_projects.test_cognito_proj.test_cognito_app.models.User',
    'APPLICATION_DOCUMENT': 'test_projects.test_cognito_proj.test_cognito_app.models.ApiKey',
    'API_PERMISSION_MODEL': 'test_projects.test_cognito_proj.test_cognito_app.models.ApiPermission',
    'API_REQUEST_PERMISSION_MODEL': 'test_projects.test_cognito_proj.test_cognito_app.models.ApiRequestPermission',
    'BYPASS_URLS': [
        ('POST', '/auth/register'),
    ],
    'SSO_TOKEN_CLASSES': [],
    'FULL_ACCESS_API_KEY_NAMES': ['test-app'],
    'MULTIPART_POST_URLS': [],
    'UNSECURED_URLS': []
}

# set test runner to nose
TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'
