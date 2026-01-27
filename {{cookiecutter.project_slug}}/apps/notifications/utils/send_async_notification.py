
from apps.notifications.models import NotificationModel
from django.contrib.auth import get_user_model
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from apps.notifications.serializers import NotificationSerializer

from typing import Tuple

User = get_user_model()

def send_async_notification(user: int, message: str) -> Tuple[bool, str]:
    try:
        user = User.objects.get(id=user)
        notification = NotificationModel.objects.create(user=user, message=message)
        serialzer = NotificationSerializer(notification)
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f'notifications_{user.id}',
            {
                'type': 'notification_message',
                'notification': serialzer.data
            }
        )

        return True, 'Notification sent successfully'
    except User.DoesNotExist:
        return False, f"User with id {user} does not exist"
    except Exception as e:
        return False, str(e)