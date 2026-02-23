from rest_framework import serializers
from .models import NotificationModel, FirebaseNotifiationModel


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationModel
        fields = ['id', 'user', 'message', 'timestamp', 'is_read']
        read_only_fields = ['id', 'user', 'message', 'timestamp']


class FirebaseNotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = FirebaseNotifiationModel
        fields = '__all__'
