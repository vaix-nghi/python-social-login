from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone

# Create your models here.

class User(models.Model):
    uid = models.CharField(max_length=150)
    provider = models.CharField(max_length=128)
    username = models.CharField(max_length=150)
    first_name = models.CharField(max_length=128,null=True,blank=True)
    last_name = models.CharField(max_length=128,null=True,blank=True)
    email = models.EmailField(null=True)
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    token_expiration = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        db_table = 'users'
        unique_together = [['uid', 'provider']]
    def set_password(self, raw_password):
        self.password = make_password(raw_password)
    
    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
    
    def is_token_expired(self):
        return self.token_expiration is None or self.token_expiration < timezone.now()
class SocialAccount(models.Model):
    user= models.ForeignKey(User, on_delete=models.CASCADE)
    provider = models.CharField(max_length=128,null=False, blank=False)
    provider_id = models.CharField(max_length=128,null=False, blank=False)
    token = models.TextField(null=False, blank=False)
    avatar = models.ImageField(null=True, blank=True)
    # extra_data = models.JSONField()
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    class Meta:
        db_table = 'social_accounts'