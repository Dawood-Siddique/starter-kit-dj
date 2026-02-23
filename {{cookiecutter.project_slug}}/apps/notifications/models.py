from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

# Create your models here.

class NotificationModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    # Add any other fields relevant to your notification model

    def __str__(self):
        return self.message

class FirebaseNotifiationModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='device_tokens')
    device_token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.device_token}"