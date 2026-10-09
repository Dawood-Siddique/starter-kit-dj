import os
from pathlib import Path
from dotenv import load_dotenv
from corsheaders.defaults import default_headers

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables
load_dotenv(BASE_DIR / '.env')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get(
    'SECRET_KEY', 'django-secure-key-add-here')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DEBUG', 'True') == 'True'

ALLOWED_HOSTS = ['*']

AUTH_USER_MODEL = 'users.User'
CSRF_TRUSTED_ORIGINS = ["http://localhost:3000", "https://localhost:3000", "http://localhost:8000",
                        "https://localhost:8000", "http://localhost:5173", "https://localhost:5173"]
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = (*default_headers, 'x-session-token')  # allauth's app client sends it
DJANGO_LOG_LEVEL = 'INFO'
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'


# Application definition

INSTALLED_APPS = [
    'daphne',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'channels',
    'channels_redis',

    # 3rd party packages
    'rest_framework',
    'corsheaders',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.mfa',
    'allauth.headless',

    'drf_spectacular',
    'drf_spectacular_sidecar',
    'django_q',
    'django_redis',


    # apps
    'apps.users',
    'apps.notifications',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

{% if cookiecutter.database == "postgresql" %}
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': '{{cookiecutter.postgres_db_name}}',
        'USER': '{{cookiecutter.postgres_user}}',
        'PASSWORD': '{{cookiecutter.postgres_password}}',
        'HOST': '{{cookiecutter.postgres_host}}',
        'PORT': '{{cookiecutter.postgres_port}}',
    }
}
{% else %}
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}
{% endif %}

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
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'allauth.headless.contrib.rest_framework.authentication.JWTTokenAuthentication',
    ),
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_THROTTLE_CLASSES': (
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ),
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day',
    },
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'config',
    'DESCRIPTION': 'Description Here',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,  # optionally disable raw schema endpoint
    'SWAGGER_UI_DIST': 'SIDECAR',  # shorthand to use the sidecar instead
    'SWAGGER_UI_FAVICON_HREF': 'SIDECAR',
    'REDOC_DIST': 'SIDECAR',
}


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
        "file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs/general.log",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "": {
            "handlers": ["console", "file"],
            "level": os.environ.get("DJANGO_LOG_LEVEL", "INFO"),
        }
    },
    "formatters": {
        "verbose": {
            "format": "{asctime} ({levelname})- {name}- {message}",
            "style": "{",
        }
    },
}


# Authentication is handled by django-allauth in headless (API-only) mode.
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

ACCOUNT_ADAPTER = 'apps.users.adapter.AccountAdapter'
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_LOGIN_METHODS = {'email'}
ACCOUNT_SIGNUP_FIELDS = ['email*', 'password1*']
ACCOUNT_EMAIL_VERIFICATION = 'mandatory'
ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = True
ACCOUNT_PASSWORD_RESET_BY_CODE_ENABLED = True

HEADLESS_ONLY = True
# Pages on the website that allauth's emails link to. HEADLESS_ONLY crashes without them.
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
HEADLESS_FRONTEND_URLS = {
    'account_confirm_email': FRONTEND_URL + '/verify-email/{key}',
    'account_reset_password': f'{FRONTEND_URL}/reset-password',
    'account_reset_password_from_key': FRONTEND_URL + '/reset-password/{key}',
    'account_signup': f'{FRONTEND_URL}/signup',
    'socialaccount_login_error': f'{FRONTEND_URL}/login',
}
HEADLESS_SERVE_SPECIFICATION = True  # API docs at /_allauth/openapi.html
HEADLESS_TOKEN_STRATEGY = 'allauth.headless.tokens.strategies.jwt.JWTTokenStrategy'
HEADLESS_JWT_ALGORITHM = 'HS256'  # signed with SECRET_KEY
HEADLESS_JWT_ACCESS_TOKEN_EXPIRES_IN = 15 * 60
HEADLESS_JWT_REFRESH_TOKEN_EXPIRES_IN = 7 * 24 * 60 * 60
HEADLESS_JWT_ROTATE_REFRESH_TOKEN = True
HEADLESS_JWT_STATEFUL_VALIDATION_ENABLED = True  # logout invalidates access tokens immediately

# Google sign-in: the frontend sends Google's id_token, allauth verifies it.
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'APPS': [{
            'client_id': os.environ.get('GOOGLE_CLIENT_ID', ''),
            'secret': os.environ.get('GOOGLE_CLIENT_SECRET', ''),
        }],
        'SCOPE': ['profile', 'email'],
    },
}
# Signing in with Google logs into the existing account with that email.
SOCIALACCOUNT_EMAIL_AUTHENTICATION = True
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True

if DEBUG:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'


CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("127.0.0.1", 6379, 1)],
        },
    },
}


# Django-Q2 Configuration
Q_CLUSTER = {
    'name': 'config',
    'workers': 4,  # Number of worker processes
    'timeout': 220,  # Seconds before a task is considered failed
    'retry': 520,  # Seconds to wait before retrying a task
    'queue_limit': 50,
    'bulk': 10,
    # 'orm': 'default',  # Use the default Django ORM database
    'redis': {
        'host': '127.0.0.1',
        'port': 6379,
        'db': 0,
    },
    'scheduler': True,

}

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/2",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        }
    }
}
