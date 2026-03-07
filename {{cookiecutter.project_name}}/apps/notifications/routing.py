from django.urls import path
from apps.notifications.consumers import AsyncNotificationsConsumer

websocket_urlpatterns = [
    path("ws/notifications/", AsyncNotificationsConsumer.as_asgi()),
]