from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.conf import settings
from django.shortcuts import redirect, render
from .models import SocialApp, User, SocialAccount
from json.decoder import JSONDecodeError
from rest_framework import status
from allauth.socialaccount.providers.google import views as google_view
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
import requests
import json
from .app_settings import (
    # SOCIALOAUTH_SITES,
    # SOCIAL_LOGIN_USER_INFO_MODEL,
    # SOCIAL_LOGIN_DONE_REDIRECT_URL,
    SOCIAL_LOGIN_ERROR_REDIRECT_URL,
    SOCIAL_LOGIN_CALLBACK_URL_PATTERN
)
# Create your views here.
BASE_URL = 'http://127.0.0.1:8000/'
GOOGLE_CALLBACK_URI = BASE_URL + 'social/account/oauth/google/login/callback/'
def social_login(request, provider):
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/auth"
        "?response_type=code"
        "&client_id={}"
        "&redirect_uri={}"
        "&scope={}"
    ).format(settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_ID'],
            GOOGLE_CALLBACK_URI," ".join(settings.SOCIALACCOUNT_PROVIDERS[provider]['SCOPE']))
    print(google_auth_url)
    return redirect(google_auth_url)

def social_login_callback(request, provider):
    code = request.GET.get('code')
    
    #Access token
    access_token =_get_access_token(request, code, provider)
    print(access_token)
    if not access_token: 
        return HttpResponse("Không thể lấy access token")
    
    #Email
    email = _get_email_request(request, access_token, provider)
    print(email)
    
    #get info
    user_info_url = settings.SOCIALACCOUNT_PROVIDERS[provider]['USER_INFO_URL']
    user_info_params = {'access_token': access_token}
    user_info_response = requests.get(user_info_url, params=user_info_params)
    if user_info_response.status_code != 200:
        return HttpResponse(user_info_response.content)
    user_info = user_info_response.json()
    email = user_info.get('email')
    print(user_info)
    
    #Signup or Signin Request
    try:
        user = User.objects.get(email=email)
        social_user = SocialAccount.objects.get(
            user=user
        )
        if social_user.provider != provider:
            return HttpResponse('no matching social type')
        if social_user is None:
            return HttpResponse('email exists but not social user')
        else:
            return HttpResponse('Đăng nhập thành công')
    except User.DoesNotExist:
        user =_create_user_and_social_account(user_info, provider, access_token)
        return HttpResponse('Đăng ký thành công')
    except SocialAccount.DoesNotExist:
        user =_create_user_and_social_account(user_info, provider, access_token)
        return HttpResponse('Đăng ký thành công')
    
    # set uid in session, then next time, this user will be auto loggin
    # request.session['uid'] = user.user_id   
    

def _get_access_token(request,code,provider):
    token_data = {
        'code': code,
        'client_id': settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_ID'],
        'client_secret': settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_SECRET'],
        'redirect_uri': GOOGLE_CALLBACK_URI,
        'grant_type': 'authorization_code'
    }
    token_url = settings.SOCIALACCOUNT_PROVIDERS[provider]['TOKEN_URL']
    token_req = requests.post(
        token_url,data=token_data)
    print(token_req)
    token_req_json = token_req.json()
    error = token_req_json.get("error")
    if error is not None:
        return HttpResponse(error)
    access_token = token_req_json.get('access_token')
    return access_token

def _get_email_request(request,access_token, provider):
    email_url = settings.SOCIALACCOUNT_PROVIDERS[provider]['EMAIL_URL']
    email_data = {
        'access_token' : access_token
    }
    email_req = requests.get(email_url,data = email_data)
    email_req_status = email_req.status_code
    if email_req_status != 200:
        return HttpResponse('Không thể truy cập email')
    email_req_json = email_req.json()
    email = email_req_json.get('email')
    print(email_req_json)
    return email

def _create_user_and_social_account(user_info, provider, access_token):
    email = user_info.get('email')
    username = user_info.get('name')
    provider_id = user_info.get('id')
    first_name = user_info.get('given_name')
    last_name = user_info.get('family_name')
    avatar = user_info.get('avatar')
    
    data = {'username': username,
                'first_name': first_name,
                'last_name':last_name,
                }
    
    user, created = User.objects.get_or_create(email=email,
                                                defaults=data)
    
    if created:
        SocialAccount.objects.create(
                                        user=user,
                                        provider=provider,
                                        provider_id=provider_id,
                                        token=access_token,
                                        avatar=avatar
                                        )
    else:
        social_account, social_created = SocialAccount.objects.get_or_create(
                                        user=user,
                                        provider=provider,
                                        defaults={
                                            "user" : user,
                                            "provider" : provider,
                                            "provider_id" : provider_id,
                                            "token" : access_token,
                                            "avatar" : avatar
                                            }
        )
    return user