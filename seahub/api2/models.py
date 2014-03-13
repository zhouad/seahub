import uuid
import hmac
from hashlib import sha1
from django.db import models

from seahub.base.fields import LowerCaseCharField

class Token(models.Model):
    """
    The default authorization token model.
    """
    key = models.CharField(max_length=40, primary_key=True)
    user = LowerCaseCharField(max_length=255, unique=True)
    created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(Token, self).save(*args, **kwargs)

    def generate_key(self):
        unique = str(uuid.uuid4())
        return hmac.new(unique, digestmod=sha1).hexdigest()

    def __unicode__(self):
        return self.key

class TokenV2(models.Model):
    """
    Device specific token
    """

    token = models.CharField(max_length=40)

    user = LowerCaseCharField(max_length=255)

    # lin-laptop
    device_name = models.CharField(max_length=40)

    # windows/linux/mac/ios/android
    platform = LowerCaseCharField(max_length=32)

    # platform version
    platform_version = LowerCaseCharField(max_length=16)

    # seafile client/app version
    client_version = LowerCaseCharField(max_length=16)

    # most recent activity
    last_used = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("token", "user"),)

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self.generate_key()
        return super(TokenV2, self).save(*args, **kwargs)

    def generate_key(self):
        unique = str(uuid.uuid4())
        return hmac.new(unique, digestmod=sha1).hexdigest()

    def __unicode__(self):
        return "TokenV2{user=%(user)s,device=%(device_name)s}" % \
            dict(user=self.user,device_name=self.device_name)
