from django.urls import path

from .views import social_login_callback, social_login
from .app_settings import SOCIAL_LOGIN_CALLBACK_URL_PATTERN


# SOCIAL_LOGIN_CALLBACK_URL_PATTERN is the OAuth2 call back url format.
# settings this in Social site which you are using the OAuth2 services.

urlpatterns = [
    path(SOCIAL_LOGIN_CALLBACK_URL_PATTERN,
        social_login_callback,
        name='social_login_callback'),
    path('social/<provider>/login/', social_login, name='social_login'),
    # path('accounts/google/login/finish/', create_user_account, name='google_login'),
    ]
