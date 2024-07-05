from django.db import models
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import User, auth

def validate_gender(value):
    if value not in ["F", "M"]:
        raise ValidationError(
            _('Invalid gender. Please use "F" for female or "M" for male.'),
            code="invalid_gender",
        )

class Jwt(models.Model):
    user = models.OneToOneField(
        User, related_name="login_user", on_delete=models.CASCADE
    )
    access = models.TextField()
    refresh = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{User.objects.get(id=self.user.id)}"

class UserModel(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    fullname = models.CharField(max_length=255)
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, null=True)
    address = models.CharField(max_length=255, null=True)
    language = models.CharField(max_length=10, default='en-NG')
    gender = models.CharField(
        max_length=1,
        validators=[validate_gender],
        help_text='Use "F" for female or "M" for male.',
    )
    profile_image = models.ImageField(upload_to="profile_images/", default=None)
    notification_token = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.email}"
    
class PairModel(models.Model):
    sender = models.ForeignKey(UserModel, on_delete=models.CASCADE, related_name="sender")
    receiver = models.ForeignKey(UserModel, on_delete=models.CASCADE, related_name="receiver")
    status = models.BooleanField(default=False)
    block = models.BooleanField(default=False)
    accepted = models.BooleanField(default=False)

class RecordModel(models.Model):
    pair = models.ForeignKey(PairModel, on_delete=models.CASCADE)
    sender = models.ForeignKey(UserModel, on_delete=models.CASCADE, related_name="record_sender")
    audio_file = models.URLField()
    language = models.CharField(max_length=255, default='en-NG')
    trans_language = models.URLField()
    delivered = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

""" class ExpoTokenModel(models.Model):
    expo_user = models.OneToOneField(UserModel, on_delete=models.CASCADE)
    token = models.CharField(max_length=255) """