import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from apps.notifications.models import NotificationModel
from apps.notifications.serializers import NotificationSerializer


class AsyncNotificationsConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']

        if not self.user or not self.user.is_authenticated:
            await self.close()
            return

        self.group_name = f'notifications_{self.user.id}'

        # Join room group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()
        await self.send(text_data=json.dumps({"message": f"Connected to notifications for user {self.user.first_name}!"}))
        await self.send_notifications()

    @database_sync_to_async
    def get_notifications(self):
        # notifications = NotificationModel.objects.filter(user=self.user, is_read=False).order_by('-timestamp')
        notifications = NotificationModel.objects.filter(
            user=self.user).order_by('-timestamp')
        serializer = NotificationSerializer(notifications, many=True)
        return serializer.data

    @database_sync_to_async
    def read_notification(self, notification_id):
        try:
            notification = NotificationModel.objects.get(
                id=notification_id, user=self.user, is_read=False)
            notification.is_read = True
            notification.save()
            return True
        except NotificationModel.DoesNotExist:
            return False

    @database_sync_to_async
    def mark_all_notifications_read(self):
        # .update() returns the number of rows updated.
        updated_count = NotificationModel.objects.filter(
            user=self.user, is_read=False).update(is_read=True)
        return updated_count > 0

    async def send_notifications(self):
        notifications_data = await self.get_notifications()
        await self.send(text_data=json.dumps({
            "type": "notification_list",
            "notifications": notifications_data
        }))

    async def handle_read_notification(self, data):
        notification_id = data.get("notification_id")
        if not isinstance(notification_id, int):
            await self.send(text_data=json.dumps({"error": "Invalid notification_id"}))
            return

        is_success = await self.read_notification(notification_id)
        if is_success:
            await self.send_notifications()
        else:
            await self.send(text_data=json.dumps({"error": "Notification not found or already read"}))

    async def handle_mark_all_read(self, data):
        is_success = await self.mark_all_notifications_read()
        if is_success:
            await self.send_notifications()
        else:
            await self.send(text_data=json.dumps({"error": "No unread notifications to mark as read"}))

    async def receive(self, text_data=None, bytes_data=None):
        try:
            data = json.loads(text_data)
            message_type = data.get("type")

            if message_type == "read_notification":
                await self.handle_read_notification(data)
            elif message_type == "mark_all_as_read":
                await self.handle_mark_all_read(data)

        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({"error": "Invalid JSON"}))

    async def disconnect(self, close_code):
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

    # Handler for messages sent to the group
    async def notification_message(self, event):
        # This method is called when a message is sent to the group.
        # We can now send the new notification data to the client.
        await self.send(text_data=json.dumps({
            "type": "new_notification",
            "notification": event["notification"]
        }))
