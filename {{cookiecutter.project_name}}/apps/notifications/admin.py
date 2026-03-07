from django.contrib import admin
from apps.notifications.models import NotificationModel, FirebaseNotifiationModel

# Register your models here.

admin.site.register(NotificationModel)
admin.site.register(FirebaseNotifiationModel)

#