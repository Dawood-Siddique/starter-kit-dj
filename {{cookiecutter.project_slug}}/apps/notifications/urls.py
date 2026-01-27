from apps.notifications.views import (
    NotificationView,
    FirebaseNotificationView,
    MarkAllNotificationsReadView
)

from django.urls import path

urlpatterns = [
    path('sync/', NotificationView.as_view(), name='notifications'),
    path('mark-all-read/', MarkAllNotificationsReadView.as_view(), name='mark-all-read'),
    path('firebase/', FirebaseNotificationView.as_view(), name='firebase-notifications'),
]