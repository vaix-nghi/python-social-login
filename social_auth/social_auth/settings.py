"""
Django settings for social_auth project.

Generated by 'django-admin startproject' using Django 5.0.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
from  django.db.backends import mysql
import os 
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-5(o9m$8g5ig_*a3kigp@vn)@-%xc-+shrj@ig_oa5^z(lk5@dd'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1','localhost']

BASE_URL = 'http://127.0.0.1:8000/'
# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'social_login',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'social_auth.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
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

WSGI_APPLICATION = 'social_auth.wsgi.application'


AUTHENTICATION_BACKENDS = [
    'social_core.backends.google.GoogleOpenId',
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.google.GoogleOAuth',
    # 'allauth.account.auth_backends.AuthenticationBackend',
    'social_core.backends.twitter.TwitterOAuth',
    'django.contrib.auth.backends.ModelBackend',
]

STATIC_URL = '/static/'
STATICFILES_DIRS = [
    BASE_DIR / 'social_auth/static'
]

# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'social_login',
        'USER': 'root',
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': 'localhost',
        'PORT': '3309',
        'OPTIONS': {
            'charset': 'utf8mb4',
            'use_unicode': True,
        },
    },
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/


# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

ACCOUNT_LOGIN_REDIRECT_URL = 'home'
ACCOUNT_LOGOUT_REDIRECT_URL = 'account_login'

# Twitter
SOCIAL_LOGIN_ERROR_REDIRECT_URL=""

TENANT ="common"

PROVIDER_DEFAULT = ['twitter','microsoft']

SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': [
            'profile',
            'email',
        ],
        'CLIENT_ID':'1073769602100-he91ac0fkhmvm6tlr2jod692vg4b00al.apps.googleusercontent.com',
        'CLIENT_SECRET':'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',
        'AUTHORIZATION_URL':'https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount',
        'TOKEN_URL':'https://oauth2.googleapis.com/token',
        'EMAIL_URL':'https://www.googleapis.com/oauth2/v1/tokeninfo',
        'USER_INFO_URL':'https://www.googleapis.com/oauth2/v1/userinfo',
        'REDIRECT_URL': BASE_URL + 'social/account/oauth/google/login/callback',
        'AUTH_PARAMS': {
            'response_type': 'code',
            'grant_type': 'authorization_code',
            'Content-Type': 'application/x-www-form-urlencoded'
            
        }
    },
    'twitter': {
        'SCOPE': [
            'tweet.read',
            'users.read',  # Request these permissions as needed
        ],
        'CLIENT_ID':'a0pVNFROWlF1R2pLQkNIWFNvVjY6MTpjaQ',
        'CLIENT_SECRET':'TM64kKGwWKYMedCZ163Fb7qin5Hhj8LTo9gBtReDVIqh2sSjQr',
        'AUTHORIZATION_URL':'https://twitter.com/i/oauth2/authorize', #https://api.twitter.com/oauth/authenticate?oauth_signature_method=HMAC-SHA1&oauth_signature=GGGfmmHwEMdcmzRTIz0QWlE19Us%3D&oauth_token=UH5qaQAAAAAAAAsqAAABj7lcDyo&oauth_callback=https%3A%2F%2Fdisqus.com%2F_ax%2Ftwitter%2Fcomplete%2F%3Fstate%3D7zWDsnfugIdxMRfASCxIQ3xJOgg7XEe4
        'TOKEN_URL': 'https://api.twitter.com/2/oauth2/token',  # Twitter-specific endpoint
        'REDIRECT_URL': BASE_URL + 'social/account/oauth/twitter/login/callback',  # Replace with your callback URL
        'USER_INFO_URL':'https://api.twitter.com/2/users/me',
        'AUTH_PARAMS': {
            'response_type': 'code',
            'grant_type': 'authorization_code'
        },
        'AUTHORIZATION': 'Basic'
    },
    'microsoft': {
        
    },
}
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = False