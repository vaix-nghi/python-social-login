from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.hashers import make_password, check_password
# Create your models here.

class SocialApp(models.Model):

    # The provider type, e.g. "google", "telegram", "saml".
    provider = models.CharField(
        verbose_name=_("provider"),
        max_length=30,
    )

    provider_id = models.CharField(
        verbose_name=_("provider ID"),
        max_length=200,
        blank=True,
    )
    name = models.CharField(verbose_name=_("name"), max_length=40)
    client_id = models.CharField(
        verbose_name=_("client id"),
        max_length=191,
        help_text=_("App ID, or consumer key"),
    )
    secret = models.CharField(
        verbose_name=_("secret key"),
        max_length=191,
        blank=True,
        help_text=_("API secret, client secret, or consumer secret"),
    )
    key = models.CharField(
        verbose_name=_("key"), max_length=191, blank=True, help_text=_("Key")
    )
    settings = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = _("social application")
        verbose_name_plural = _("social applications")
        db_table = 'social_account'
    def __str__(self):
        return self.name

class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    first_name = models.CharField(max_length=128,blank=True)
    last_name = models.CharField(max_length=128,blank=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    class Meta:
        db_table = 'users'
    def set_password(self, raw_password):
        self.password = make_password(raw_password)
    
    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
class SocialAccount(models.Model):
    user= models.ForeignKey(User, on_delete=models.CASCADE)
    provider = models.CharField(max_length=128,null=False, blank=False)
    provider_id = models.CharField(max_length=128,null=False, blank=False)
    token = models.CharField(max_length=300,null=False, blank=False)
    avatar = models.ImageField(null=True, blank=True)
    # extra_data = models.JSONField()
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    class Meta:
        db_table = 'social_accounts'