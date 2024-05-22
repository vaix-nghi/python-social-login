
from django.http import HttpResponse
from django.conf import settings
from django.shortcuts import redirect
from .models import User, SocialAccount
import requests
from urllib.parse import urlencode
from django.contrib.auth import logout
import hashlib
import base64
import os
import random
import string

def social_login(request, provider):
    authorization_url = settings.SOCIALACCOUNT_PROVIDERS[provider]['AUTHORIZATION_URL']
    client_id = settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_ID']
    redirect_uri = settings.SOCIALACCOUNT_PROVIDERS[provider]['REDIRECT_URL']
    scope = " ".join(settings.SOCIALACCOUNT_PROVIDERS[provider]['SCOPE'])
    
    #generate codechallange and codeverifier
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = generate_state()
    
    query_params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': scope,
        
    }
    if provider =='twitter':
        request.session['oauth_state'] = state
        request.session['code_verifier'] = code_verifier
        query_params.update({
            'state': state,  # Tạo chuỗi ngẫu nhiên để bảo mật
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',  # Phương pháp băm SHA-256
        })
        
    auth_url = f"{authorization_url}?{urlencode(query_params)}"
    
    print("url: "+ auth_url)
    return redirect( auth_url)

def social_login_callback(request, provider):
    code = request.GET.get('code')
    state = request.GET.get('state')
    
    saved_state = request.session.pop('oauth_state', None)
    
    print(111111111)
    if provider == 'twitter' and state != saved_state:
        return HttpResponse("State value did not match")
    #Access token
    print(111111112)
    
    access_token =_get_access_token(request, code, provider)
    print(access_token)
    print(111111113)
    
    if not access_token: 
        return HttpResponse("Không thể lấy access token")
    
    # #Email
    # email = _get_email_request(access_token, provider)
    # print(email)
    
    #get info
    user_info_url = settings.SOCIALACCOUNT_PROVIDERS[provider]['USER_INFO_URL']
    # user_info_params = {
        
    #     'access_token': access_token
    #     }
    print(111111114)
    
    headers = {
        'Authorization': f'Bearer {access_token}',
    }
    user_info_response = requests.get(user_info_url, headers=headers)
    print('user_info_response',user_info_response)
    
    if user_info_response.status_code != 200:
        return HttpResponse('lỗi không lấy được user info.',user_info_response.status_code)
    print(2222)
    user_info = user_info_response.json()
    email = user_info.get('email')
    print(user_info)
    #Signup or Signin Request
    try:
        print(12)
        user = User.objects.get(email=email)
        social_user = SocialAccount.objects.get(
            user=user
        )
        if social_user.provider != provider:
            return HttpResponse('no matching social type')
        if social_user is None:
            return HttpResponse('email exists but not social user')
        else:
            #TODO: Login app
            return HttpResponse('Đăng nhập thành công')
    except User.DoesNotExist:
        print(1)
        
        user =_create_user_and_social_account(user_info, provider, access_token)
        #TODO: Login app
        return HttpResponse('Đăng ký thành công')
    except SocialAccount.DoesNotExist:
        print(3)
        user =_create_user_and_social_account(user_info, provider, access_token)
        #TODO: Login app
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
        'grant_type': 'authorization_code'  #can choose refresh token
    }
    if provider == 'twitter':
        encoded_credentials = base64.b64encode(f"{settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_ID']}:{settings.SOCIALACCOUNT_PROVIDERS[provider]['CLIENT_SECRET']}".encode()).decode()
        token_data.update({
            'code_verifier': code_verifier,
        })
        headers.update({
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {encoded_credentials}'
        })
    token_url = settings.SOCIALACCOUNT_PROVIDERS[provider]['TOKEN_URL']
    #send request post
    token_req = requests.post(
        token_url,data=token_data,headers=headers)
    
    print("token_url: ",token_req)
    
    token_req_json = token_req.json()
    error = token_req_json.get("error")
    print(token_req_json)
    
    if error is not None:
        return HttpResponse(error)
    access_token = token_req_json.get('access_token')
    
    return access_token

def _get_email_request(access_token, provider):
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
    if provider == 'twitter':
        user_info = user_info.get('data')
    email = user_info.get('email')
    username = user_info.get('name')
    provider_id = user_info.get('id')
    first_name = user_info.get('given_name')
    last_name = user_info.get('family_name')
    avatar = user_info.get('avatar')
    print(user_info)
    data = {
            'username': username if username else '{last_name}@{provider}.com'  ,
            'first_name': first_name,
            'last_name':last_name,  
        }
    
    user, created = User.objects.get_or_create(email=email if email else '{last_name}@{provider}.com',
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