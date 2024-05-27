import yaml
from requests_oauthlib import OAuth2Session
import os
import time


def store_session(request, token = None, code_verifier = None, state = None):
    if state != None:
      request.session['oauth_token'] = token
    if state != None:
      request.session['oauth_state'] = state
    if code_verifier != None:
      request.session['code_verifier'] = code_verifier  

def get_query_params(client_id, redirect_uri,scope) -> dict :
  return  {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': scope,
        }      

def store_user(request, user):
    request.session['user'] = {
        'is_authenticated': True,
        'name': user.first_name,
        'uid': user.uid,
        'provider' : user.provider
    }





