from django.conf import settings

SOCIAL_LOGIN_ERROR_REDIRECT_URL = settings.SOCIAL_LOGIN_ERROR_REDIRECT_URL

SOCIAL_LOGIN_CALLBACK_URL_PATTERN = getattr(settings,
                                            'SOCIAL_LOGIN_CALLBACK_URL_PATTERN',
                                            'social/account/oauth/<provider>/login/callback/'
                                            )

