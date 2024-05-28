import hashlib
import base64
import os
import random
import string
import requests
from datetime import timedelta
from django.utils import timezone
from django.http import HttpResponse
from django.conf import settings
from django.shortcuts import redirect
from .models import User, SocialAccount
from urllib.parse import urlencode
from .auth_helper import store_session, store_user

def social_login(request, provider):
    authorization_url = settings.SOCIALACCOUNT_PROVIDERS[provider]['AUTHORIZATION_URL']
    client_id = settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_ID']
    redirect_uri = settings.SOCIALACCOUNT_PROVIDERS[provider]['REDIRECT_URL']
    scope = " ".join(settings.SOCIALACCOUNT_PROVIDERS[provider]['SCOPE'])
    
    #generate codechallange, codeverifier and state
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = generate_state()
    
    query_params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': scope,
        
    }
    if provider in settings.PROVIDER_DEFAULT:
        store_session(request=request,token=None, code_verifier=code_verifier, state=state) 
        query_params.update({
            'state': state,  # Tạo chuỗi ngẫu nhiên để bảo mật
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',  # Phương pháp băm SHA-256
        })
    if provider =='microsoft':
        query_params.update({
            'response_mode':'query'
        })
    
    auth_url = f"{authorization_url}?{urlencode(query_params)}"
    
    print("url: "+ auth_url)
    # user = compare_expire_time(request)
    # if user and not user.is_token_expired():
    #     auth_url = redirect_uri
    
    return redirect(auth_url)

def social_login_callback(request, provider):
    code = request.GET.get('code')
    if not code:
        return HttpResponse("No code provided")
    state = request.GET.get('state')
    
    saved_state = request.session.pop('oauth_state', None)
    if provider in settings.PROVIDER_DEFAULT and state != saved_state:
        return HttpResponse("State value did not match ",state)
    #Access token
    access_token =_get_access_token(request, code, provider)
    print(access_token)
    
    if access_token == 'error': 
        return HttpResponse("Không thể lấy access token")
    
    #get info
    user_info = _get_info_users(provider, access_token)
    if user_info == 'error':
        return HttpResponse('Lỗi không thể lấy được user info')
    
    email = user_info.get('email') 
    uid = email 
    if provider == 'twitter' :
        email = f'{user_info.get("data").get("username")}@{provider}.com'
        uid = user_info.get("data").get("username")
    if provider == 'microsoft':
        email = user_info.get('mail') 
        uid = email
    print('user info: ',email)
    #Signup or Signin Request
    try:
        user = User.objects.get(uid=uid, provider=provider)
        social_user = SocialAccount.objects.get(
            user=user
        )
        store_user(request, user)
        #save access token into database every time u login
        social_user.token = access_token
        social_user.token_expiration  = timezone.now() + timedelta(hours=1)
        social_user.save()
        
        if social_user.provider != provider:
            return HttpResponse('no matching social type')
        if social_user is None:
            return HttpResponse('email exists but not social user')
        else:
            #TODO: Login app
            return HttpResponse('Đăng nhập thành công')
    except User.DoesNotExist:
        
        user =_create_user_and_social_account(user_info, provider, access_token)
        #TODO: Login app
        store_user(request, user)
        return HttpResponse('Đăng ký thành công')
    except SocialAccount.DoesNotExist:
        user =_create_user_and_social_account(user_info, provider, access_token)
        #TODO: Login app
        store_user(request, user)
        return HttpResponse('Đăng ký thành công')
    
    # TODO: set uid in session, then next time, this user will be auto loggin
    # request.session['uid'] = user.user_id   

def _get_access_token(request, code, provider):
    
    code_verifier = request.session.pop('code_verifier', None)
    headers = {}
    
    token_data = {
        'code': code,
        'client_id': settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_ID'],
        'client_secret': settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_SECRET'],
        'redirect_uri': settings.SOCIALACCOUNT_PROVIDERS[provider]['REDIRECT_URL'],
        'grant_type': 'authorization_code'  #can choose refresh_token OR  authorization_code
    }
    
    if provider in settings.PROVIDER_DEFAULT:
        encoded_credentials = base64.b64encode(f"{settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_ID']}:{settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_SECRET']}".encode()).decode()
        print('encoded_credentials: ',encoded_credentials)
        token_data.update({
            'code_verifier': code_verifier,
        })
        headers.update({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'{settings.SOCIALACCOUNT_PROVIDERS[provider]["AUTHORIZATION"]} {encoded_credentials}'
        })
        
    token_url = settings.SOCIALACCOUNT_PROVIDERS[provider]['TOKEN_URL']
    
    #send request post
    
    token_req = requests.post(
        token_url,data=token_data,headers=headers)
    print("token_req: ",token_req.reason)
    
    token_req_json = token_req.json()
    
    print("token_req_json: ",token_req_json)
    if token_req.status_code !=200:
        return 'error'
    access_token = token_req_json.get('access_token')
    store_session(request=request, token=access_token)

    return access_token

def _create_user_and_social_account(user_info, provider, access_token):
    if provider == 'twitter':
        user_info = user_info.get('data')
    username = user_info.get('name') 
    provider_id = user_info.get('id')
    email = user_info.get('email') 
    first_name = user_info.get('given_name') 
    last_name = user_info.get('family_name')
    avatar = user_info.get('picture')
    
    
    if provider == 'twitter':
        username = user_info.get('username')
        email = f'{username}@{provider}.com'
        first_name = user_info.get('name')
        
    if provider == 'microsoft':
        username = user_info.get('displayName')
        email = user_info.get('mail') 
        last_name = user_info.get('surname')
        first_name = user_info.get('givenName') 
        
    uid = email if provider != 'twitter' else username
    print(user_info)
    
    data = {
            'username': username  ,
            'first_name': first_name ,
            'last_name':last_name,  
            'email' :email,
            'provider':provider,
            'token_expiration' : timezone.now() + timedelta(hours=1)
        }
    
    
    user, created = User.objects.get_or_create(uid=uid,
                                                provider=provider,
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
        SocialAccount.objects.get_or_create(
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
def generate_code_verifier():
    # Tạo một chuỗi ngẫu nhiên dài 32 byte, sau đó mã hóa nó bằng Base64 URL-safe và loại bỏ các dấu '='
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')

def generate_code_challenge(verifier):
    # Băm mã xác minh bằng SHA-256, sau đó mã hóa kết quả bằng Base64 URL-safe và loại bỏ các dấu '='
    challenge = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(challenge).rstrip(b'=').decode('utf-8')
# Hàm tạo giá trị state ngẫu nhiên
def generate_state():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def _get_info_users(provider, access_token):
    user_info_url = settings.SOCIALACCOUNT_PROVIDERS[provider]['USER_INFO_URL']

    headers = {
        'Authorization': f'Bearer {access_token}',
    }
        
    user_info_response = requests.get(user_info_url, headers=headers)
    print('user_info_response',user_info_response)

    print(user_info_response.status_code)
    if user_info_response.status_code != 200:
        return 'error'
    
    user_info = user_info_response.json()
    print('user_info: ', user_info)
    return user_info

def compare_expire_time(request):
    print(request.session.get("user"))
    if request.session.get("user"):
        uid = request.session.get("user").pop('uid') 
        provider = request.session["user"].pop('provider') 
        
        user = User.objects.get(uid=uid, provider=provider)
        
        if user:
            return user
    return None